#!/usr/bin/env node
import { Command } from "commander";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import process from "node:process";
import path from "node:path";
import { tmpdir } from "node:os";
import { compilePolicy } from "@freedomofpress/sigsum/dist/policyCompiler";
import { RawPublicKey } from "@freedomofpress/sigsum/dist/types";
import { verifyHashWithCompiledPolicy } from "@freedomofpress/sigsum/dist/verify";
import { canonicalize } from "./canonicalize";
import { EnrollmentInput, buildEnrollmentObject, loadEnrollment } from "./enrollment";
import {
  ManifestDocument,
  canonicalizeManifestBody,
  loadManifestConfig,
  loadManifestDocument,
  scanDirectory,
} from "./manifest";
import { loadBundleDocument } from "./bundle";
import { deriveSignerKeyFromPrivateKey, fetchTimestampFromPolicy, runSigsumSubmit } from "./sigsum";
import { decodeKeyMaterial, decodePolicyBytes, hashPolicyBytes, toBase64Url } from "./utils";

async function writeMaybe(filePath: string | undefined, contents: string): Promise<void> {
  if (filePath) {
    await writeFile(filePath, contents);
  } else {
    process.stdout.write(contents + "\n");
  }
}

function collectSigner(value: string, previous: string[]): string[] {
  previous.push(value);
  return previous;
}

const program = new Command();
program.name("webcat-cli").description("Utilities for WEBCAT enrollment and manifest generation and validation");

const enrollment = program.command("enrollment").description("Enrollment helpers");

enrollment
  .command("create")
  .description("Create an enrollment definition")
  .requiredOption("-p, --policy-file <path>", "Sigsum policy file to compile")
  .requiredOption("-s, --signer <key>", "Signer public key (hex or base64)", collectSigner, [] as string[])
  .requiredOption("-t, --threshold <k>", "Threshold for signature approval")
  .requiredOption("-m, --max-age <seconds>", "Maximum age in seconds")
  .requiredOption("-c, --cas-url <url>", "CAS https URL")
  .option("-o, --output <path>", "Write result to file instead of stdout")
  .action(async (options: {
    policyFile: string;
    signer: string[];
    threshold: number | string;
    maxAge: number | string;
    casUrl: string;
    output?: string;
  }) => {
    const policyText = await readFile(options.policyFile, "utf8");
    const compiled = await compilePolicy(policyText);
    const policyEncoded = toBase64Url(compiled);

    const enrollmentObject = buildEnrollmentObject({
      policy: policyEncoded,
      signers: options.signer,
      threshold: options.threshold,
      maxAge: options.maxAge,
      casUrl: options.casUrl,
    });

    const json = JSON.stringify(enrollmentObject, null, 2);
    await writeMaybe(options.output, json);
  });

enrollment
  .command("canonicalize")
  .description("Canonicalize an enrollment JSON file")
  .requiredOption("-e, --enrollment <path>", "Enrollment file to canonicalize")
  .option("-o, --output <path>", "Write canonical JSON to a file")
  .action(async (options: { input: string; output?: string }) => {
    const enrollmentObject = await loadEnrollment(options.input);
    const canonical = canonicalize(enrollmentObject);
    await writeMaybe(options.output, canonical);
  });

enrollment
  .command("hash")
  .description("Canonicalize and hash an enrollment file")
  .requiredOption("-i, --input <path>", "Enrollment file to hash")
  .action(async (options: { input: string }) => {
    const enrollmentObject = await loadEnrollment(options.input);
    const canonical = canonicalize(enrollmentObject);
    const digest = createHash("sha256").update(canonical).digest();
    const encodedHash = toBase64Url(digest);
    process.stdout.write(encodedHash + "\n");
  });


const manifest = program.command("manifest").description("Manifest helpers");

manifest
  .command("generate")
  .description("Generate a manifest from a directory and config")
  .requiredOption("-c, --config <path>", "Manifest config JSON file")
  .requiredOption("-d, --directory <path>", "Directory containing site assets")
  .requiredOption("-p, --policy-file <path>", "Sigsum policy file for timestamps")
  .option("-o, --output <path>", "Write manifest to a file instead of stdout")
  .action(
    async (options: {
      config: string;
      directory: string;
      policyFile: string;
      output?: string;
    }) => {
      const [config, scan, policyText] = await Promise.all([
        loadManifestConfig(options.config),
        scanDirectory(options.directory),
        readFile(options.policyFile, "utf8"),
      ]);
      const indexKey = "/" + config.default_index.replace(/^\/+/, "");
      if (!scan.files.has(indexKey)) {
        throw new Error(`default_index ${config.default_index} was not found in the scanned files`);
      }
      if (!scan.files.has(config.default_fallback)) {
        throw new Error(`default_fallback ${config.default_fallback} was not found in the scanned files`);
      }
      const timestamp = await fetchTimestampFromPolicy(policyText);
      const filesObject = Object.fromEntries(
        Array.from(scan.files.entries()).sort(([a], [b]) => a.localeCompare(b))
      );
      const wasmList = Array.from(new Set([...config.wasm, ...scan.wasm])).sort();
      const extraCsp = Object.fromEntries(
        Object.entries(config.extra_csp).sort(([a], [b]) => a.localeCompare(b))
      );
      const manifestDocument: ManifestDocument = {
        manifest: {
          app: config.app,
          version: config.version,
          default_csp: config.default_csp,
          files: filesObject,
          default_index: config.default_index,
          default_fallback: config.default_fallback,
          timestamp,
          wasm: wasmList,
          extra_csp: extraCsp,
        },
        signatures: {},
      };
      const json = JSON.stringify(manifestDocument, null, 2);
      await writeMaybe(options.output, json);
    }
  );

manifest
  .command("sign")
  .description("Use sigsum-submit to sign a manifest and attach the proof")
  .requiredOption("-i, --input <path>", "Manifest file to sign")
  .requiredOption("-p, --policy-file <path>", "Sigsum trust policy file for sigsum-submit")
  .requiredOption("-k, --key <path>", "Sigsum private key for signing")
  .option("-o, --output <path>", "Write updated manifest to a file")
  .action(
    async (options: {
      input: string;
      policyFile: string;
      key: string;
      signer: string;
      output?: string;
    }) => {
      const document = await loadManifestDocument(options.input);
      const canonicalManifest = canonicalizeManifestBody(document);
      const signerKey = await deriveSignerKeyFromPrivateKey(options.key);
      if (document.signatures[signerKey]) {
        throw new Error("manifest already contains a signature for this signer");
      }
      const tempDir = await mkdtemp(path.join(tmpdir(), "webcat-manifest-"));
      const tempFile = path.join(tempDir, "manifest.json");
      try {
        await writeFile(tempFile, canonicalManifest);
        await runSigsumSubmit(options.policyFile, options.key, tempFile);
        const proofPath = `${tempFile}.proof`;
        let proofText: string;
        try {
          const proofRaw = await readFile(proofPath, "utf8");
          proofText = proofRaw.trim();
        } catch (err: any) {
          throw new Error(`failed to read Sigsum proof (${err.message})`);
        }
        if (proofText.length === 0) {
          throw new Error("Sigsum proof was empty");
        }
        document.signatures[signerKey] = proofText;
        const json = JSON.stringify(document, null, 2);
        await writeMaybe(options.output, json);
      } finally {
        await rm(tempDir, { recursive: true, force: true });
      }
    }
  );

manifest
  .command("canonicalize")
  .description("Canonicalize a manifest JSON file")
  .requiredOption("-i, --input <path>", "Manifest file to canonicalize")
  .option("-o, --output <path>", "Write canonical JSON to a file")
  .action(async (options: { input: string; output?: string }) => {
    const document = await loadManifestDocument(options.input);
    const canonical = canonicalizeManifestBody(document);
    await writeMaybe(options.output, canonical);
  });

manifest
  .command("hash")
  .description("Canonicalize and hash a manifest file")
  .requiredOption("-m, --manifest <path>", "Manifest file to hash")
  .action(async (options: { input: string }) => {
    const document = await loadManifestDocument(options.input);
    const canonical = canonicalizeManifestBody(document);
    const digest = createHash("sha256").update(canonical).digest();
    process.stdout.write(toBase64Url(digest) + "\n");
  });

manifest
  .command("verify")
  .description(
    "Verify that a manifest (or bundle) satisfies the enrollment signer threshold",
  )
  .argument(
    "<bundle>",
    "Path to a bundle JSON file",
  )
  .argument(
    "[manifest]",
    "Path to a signed manifest JSON file (omit when providing a bundle)",
  )
  .action(
    async (primaryPath: string, manifestPath?: string) => {
      let enrollment: EnrollmentInput;
      let manifestDocument: ManifestDocument;

      if (manifestPath) {
        enrollment = await loadEnrollment(primaryPath);
        manifestDocument = await loadManifestDocument(manifestPath);
      } else {
        const bundle = await loadBundleDocument(primaryPath);
        enrollment = bundle.enrollment;
        manifestDocument = bundle.manifest;
      }

      const canonicalManifest = canonicalizeManifestBody(manifestDocument);
      const manifestHash = new Uint8Array(
        createHash("sha256").update(canonicalManifest).digest(),
      );
      const compiledPolicy = decodePolicyBytes(enrollment.policy);
      const policyHash = hashPolicyBytes(enrollment.policy);

      const signerResults: { signer: string; ok: boolean; message?: string }[] = [];
      let verified = 0;

      for (const signer of enrollment.signers) {
        const proofText = manifestDocument.signatures[signer];
        if (!proofText) {
          signerResults.push({ signer, ok: false, message: "signature missing" });
          continue;
        }
        try {
          const signerKey = new RawPublicKey(
            new Uint8Array(decodeKeyMaterial(signer, "enrollment signer")),
          );
          const ok = await verifyHashWithCompiledPolicy(
            manifestHash,
            signerKey,
            compiledPolicy,
            proofText,
          );
          if (ok) {
            verified += 1;
            signerResults.push({ signer, ok: true });
          } else {
            signerResults.push({ signer, ok: false, message: "invalid proof" });
          }
        } catch (err: any) {
          signerResults.push({ signer, ok: false, message: err.message });
        }
      }

      for (const result of signerResults) {
        const status = result.ok ? "OK" : "FAIL";
        const extra = result.message ? ` (${result.message})` : "";
        process.stdout.write(`Signer ${result.signer}: ${status}${extra}\n`);
      }

      const passed = verified >= enrollment.threshold;
      const summaryStatus = passed ? "VERIFIED" : "FAILED";
      process.stdout.write(
        `${summaryStatus}: ${verified}/${enrollment.threshold} required signatures verified\n`,
      );
      process.stdout.write(`Enrollment policy hash: ${policyHash}\n`);
    },
  );

const bundle = program.command("bundle").description("Bundle helpers");

bundle
  .command("create")
  .description("Create a bundle from enrollment and a signed manifest")
  .requiredOption("-e, --enrollment <path>", "Enrollment JSON file")
  .requiredOption("-m, --manifest <path>", "Signed manifest JSON file")
  .option("-o, --output <path>", "Write bundle JSON to a file")
  .action(
    async (options: { enrollment: string; manifest: string; output?: string }) => {
      const [enrollment, manifestDocument] = await Promise.all([
        loadEnrollment(options.enrollment),
        loadManifestDocument(options.manifest),
      ]);
      const bundleDocument = {
        enrollment,
        manifest: manifestDocument.manifest,
        signatures: manifestDocument.signatures,
      };
      const json = JSON.stringify(bundleDocument, null, 2);
      await writeMaybe(options.output, json);
    }
  );

if (process.env.NODE_ENV !== "test") {
  program.parseAsync(process.argv).catch((err: any) => {
    process.stderr.write(`Error: ${err.message}\n`);
    process.exit(1);
  });
}
