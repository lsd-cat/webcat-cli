#!/usr/bin/env node
import { Command } from "commander";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import process from "node:process";
import path from "node:path";
import { tmpdir } from "node:os";
import { compilePolicy } from "@freedomofpress/sigsum/dist/policyCompiler";
import { parsePolicyText } from "@freedomofpress/sigsum/dist/config";
import { Hash, KeyHash, Leaf, RawPublicKey, Signature } from "@freedomofpress/sigsum/dist/types";
import { verifyHashWithCompiledPolicy } from "@freedomofpress/sigsum/dist/verify";
import { SigsumProof } from "@freedomofpress/sigsum/dist/proof";
import { Updater } from "tuf-js";
import { canonicalize } from "./canonicalize";
import { EnrollmentInput, buildEnrollmentObject, loadEnrollment } from "./enrollment";
import { writeCasObject } from "./cas";
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

const SIGSTORE_TUF_BASE_URL = "https://tuf-repo-cdn.sigstore.dev";
const SIGSTORE_TUF_ROOT_URL = `${SIGSTORE_TUF_BASE_URL}/1.root.json`;
const SIGSTORE_TUF_TARGETS_URL = `${SIGSTORE_TUF_BASE_URL}/targets`;
const SIGSTORE_TRUSTED_ROOT_TARGET = "trusted_root.json";

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

async function fetchSigstoreCommunityTrustedRoot(): Promise<string> {
  const tempDir = await mkdtemp(path.join(tmpdir(), "webcat-sigstore-tuf-"));
  try {
    const rootResponse = await fetch(SIGSTORE_TUF_ROOT_URL);
    if (!rootResponse.ok) {
      throw new Error(
        `failed to download Sigstore TUF root (${rootResponse.status} ${rootResponse.statusText})`,
      );
    }
    const rootText = await rootResponse.text();
    await writeFile(path.join(tempDir, "root.json"), rootText);

    const updater = new Updater({
      metadataDir: tempDir,
      metadataBaseUrl: SIGSTORE_TUF_BASE_URL,
      targetDir: tempDir,
      targetBaseUrl: SIGSTORE_TUF_TARGETS_URL,
      config: { userAgent: "webcat-cli" },
    });
    await updater.refresh();

    const targetInfo = await updater.getTargetInfo(SIGSTORE_TRUSTED_ROOT_TARGET);
    if (!targetInfo) {
      throw new Error("Sigstore trusted_root.json target not found in the TUF repository");
    }
    const targetPath = await updater.downloadTarget(targetInfo);
    return await readFile(targetPath, "utf8");
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

function parseTrustedRootJson(value: string, source: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("must be a JSON object");
    }
    return parsed as Record<string, unknown>;
  } catch (err: any) {
    throw new Error(`failed to parse trusted root from ${source}: ${err.message}`);
  }
}

const program = new Command();
program.name("webcat-cli").description("Utilities for WEBCAT enrollment and manifest generation and validation");

const enrollment = program.command("enrollment").description("Enrollment helpers");

enrollment
  .command("create")
  .description("Create an enrollment definition")
  .option("-p, --policy-file <path>", "Sigsum policy file to compile")
  .option("-s, --signer <key>", "Signer public key (hex or base64)", collectSigner, [] as string[])
  .option("-t, --threshold <k>", "Threshold for signature approval")
  .option("-m, --max-age <seconds>", "Maximum age in seconds")
  .option("-c, --cas-url <url>", "CAS https URL")
  .option("--type <type>", "Enrollment type (sigsum or sigstore)", "sigsum")
  .option("--trusted-root <path>", "Sigstore trusted root file")
  .option("--community-trusted-root", "Fetch the Sigstore community trusted root via TUF")
  .option("--issuer <value>", "Sigstore issuer")
  .option("--identity <value>", "Sigstore identity")
  .option("-o, --output <path>", "Write result to file instead of stdout")
  .action(async (options: {
    policyFile?: string;
    signer: string[];
    threshold?: number | string;
    maxAge?: number | string;
    casUrl?: string;
    type?: string;
    trustedRoot?: string;
    communityTrustedRoot?: boolean;
    issuer?: string;
    identity?: string;
    output?: string;
  }) => {
    const enrollmentType = options.type ?? "sigsum";
    if (enrollmentType !== "sigsum" && enrollmentType !== "sigstore") {
      throw new Error("enrollment type must be 'sigsum' or 'sigstore'");
    }

    let enrollmentObject: EnrollmentInput;
    if (enrollmentType === "sigsum") {
      if (!options.policyFile) {
        throw new Error("--policy-file is required for sigsum enrollments");
      }
      if (!options.threshold) {
        throw new Error("--threshold is required for sigsum enrollments");
      }
      if (!options.maxAge) {
        throw new Error("--max-age is required for sigsum enrollments");
      }
      if (!options.casUrl) {
        throw new Error("--cas-url is required for sigsum enrollments");
      }

      const policyText = await readFile(options.policyFile, "utf8");
      const compiled = await compilePolicy(policyText);
      const policyEncoded = toBase64Url(compiled);
      const parsedPolicy = await parsePolicyText(policyText);
      const logsEntries = await Promise.all(
        Array.from(parsedPolicy.logs.values()).map(async (entity) => {
          const rawKey = await crypto.subtle.exportKey("raw", entity.publicKey.key);
          const key = toBase64Url(new Uint8Array(rawKey));
          const url = typeof entity.url === "string" ? entity.url : "";
          return [key, url] as const;
        })
      );
      logsEntries.sort(([a], [b]) => a.localeCompare(b));
      const logs = Object.fromEntries(logsEntries);

      enrollmentObject = buildEnrollmentObject({
        type: "sigsum",
        policy: policyEncoded,
        signers: options.signer,
        threshold: options.threshold,
        maxAge: options.maxAge,
        casUrl: options.casUrl,
        logs,
      });
    } else {
      if (options.communityTrustedRoot && options.trustedRoot) {
        throw new Error("use either --trusted-root or --community-trusted-root for sigstore enrollments");
      }
      if (!options.trustedRoot && !options.communityTrustedRoot) {
        throw new Error("--trusted-root or --community-trusted-root is required for sigstore enrollments");
      }
      if (!options.issuer) {
        throw new Error("--issuer is required for sigstore enrollments");
      }
      if (!options.identity) {
        throw new Error("--identity is required for sigstore enrollments");
      }
      const trustedRoot = options.communityTrustedRoot
        ? parseTrustedRootJson(
            await fetchSigstoreCommunityTrustedRoot(),
            "Sigstore TUF community trusted root",
          )
        : parseTrustedRootJson(
            await readFile(options.trustedRoot, "utf8"),
            options.trustedRoot,
          );
      enrollmentObject = buildEnrollmentObject({
        type: "sigstore",
        trustedRoot,
        issuer: options.issuer,
        identity: options.identity,
      });
    }

    const json = JSON.stringify(enrollmentObject, null, 2);
    const { hash, filePath } = await writeCasObject(json);
    process.stdout.write(`Saved enrollment to ${filePath} (sha256=${hash}).\n`);
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
        const proof = await SigsumProof.fromAscii(proofText);
        const messageHash = createHash("sha256").update(canonicalManifest).digest();
        const checksum = new Hash(createHash("sha256").update(messageHash).digest());
        const leaf = new Leaf(checksum, new Signature(proof.leaf.Signature.bytes), new KeyHash(proof.leaf.KeyHash.bytes));
        const leafBytes = leaf.toBytes();
        const { hash: leafHash, filePath: leafPath } = await writeCasObject(leafBytes, { upload: true });
        process.stdout.write(`Saved raw Sigsum leaf to ${leafPath} (sha256=${leafHash}).\n`);
        const { hash: checksumHash, filePath: checksumPath } = await writeCasObject(messageHash, {
          upload: true,
        });
        process.stdout.write(`Saved Sigsum checksum payload to ${checksumPath} (sha256=${checksumHash}).\n`);
        const { hash: manifestHash, filePath: manifestPath } = await writeCasObject(canonicalManifest, {
          upload: true,
        });
        process.stdout.write(`Saved canonical manifest to ${manifestPath} (sha256=${manifestHash}).\n`);
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
      if (enrollment.type !== "sigsum") {
        throw new Error("manifest verification is only supported for sigsum enrollments");
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
