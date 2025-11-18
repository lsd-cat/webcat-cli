#!/usr/bin/env node
import { Command } from "commander";
import { spawn } from "node:child_process";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import process from "node:process";
import path from "node:path";
import { tmpdir } from "node:os";
import { compilePolicy } from "sigsum/dist/policyCompiler";
import { parsePolicyText } from "sigsum/dist/config";
import {
  hashKey,
  verifyCosignedTreeHead,
  verifySignedTreeHead,
} from "sigsum/dist/crypto";
import { hexToBase64, hexToUint8Array } from "sigsum/dist/encoding";
import { Base64KeyHash, Hash, RawPublicKey, Signature } from "sigsum/dist/types";
import { verifyHashWithCompiledPolicy } from "sigsum/dist/verify";
import { canonicalize } from "./canonicalize";

export interface EnrollmentInput {
  policy: string;
  signers: string[];
  threshold: number;
  max_age: number;
  cas_url: string;
}

export interface EnrollmentOptions {
  policy: string;
  signers: string[];
  threshold: number | string;
  maxAge: number | string;
  casUrl: string;
}

const WEEK_SECONDS = 7 * 24 * 60 * 60;
const YEAR_SECONDS = 365 * 24 * 60 * 60;
const HEX_RE = /^[0-9a-fA-F]+$/;
const WASM_EXTENSION = ".wasm";

interface ManifestConfig {
  app: string;
  version: string;
  default_csp: string;
  default_index: string;
  default_fallback: string;
  wasm: string[];
  extra_csp: Record<string, string>;
}

interface ManifestContent extends ManifestConfig {
  files: Record<string, string>;
  timestamp: string;
}

interface ManifestDocument {
  manifest: ManifestContent;
  signatures: Record<string, string>;
}

interface DirectoryScanResult {
  files: Map<string, string>;
  wasm: Set<string>;
}

function toBase64Url(input: Uint8Array | Buffer): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function decodeKeyMaterial(value: string, name: string): Buffer {
  const trimmed = value.trim();
  let bytes: Buffer;

  if (HEX_RE.test(trimmed)) {
    if (trimmed.length % 2 !== 0) {
      throw new Error(`${name} must contain an even number of hex characters`);
    }
    bytes = Buffer.from(trimmed, "hex");
  } else {
    const normalized = trimmed.replace(/-/g, "+").replace(/_/g, "/");
    try {
      bytes = Buffer.from(normalized, "base64");
    } catch (err: any) {
      throw new Error(`invalid base64 for ${name}: ${err.message}`);
    }
  }

  if (bytes.length !== 32) {
    throw new Error(`${name} must be 32 bytes (ed25519 public keys)`);
  }

  return bytes;
}

function parseSignerKey(value: string): string {
  return toBase64Url(decodeKeyMaterial(value, "signer keys"));
}

function parseInteger(value: number | string, name: string): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(n) || n < 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return n;
}

function validateMaxAge(maxAge: number): void {
  if (maxAge <= WEEK_SECONDS) {
    throw new Error("max-age must be larger than one week");
  }
  if (maxAge >= YEAR_SECONDS) {
    throw new Error("max-age must be smaller than one year");
  }
}

function validateCasUrl(urlString: string): void {
  let parsed: URL;
  try {
    parsed = new URL(urlString);
  } catch (err: any) {
    throw new Error(`invalid CAS URL: ${err.message}`);
  }
  if (parsed.protocol !== "https:") {
    throw new Error("CAS URL must use https://");
  }
  if (!parsed.hostname) {
    throw new Error("CAS URL must include a hostname");
  }
}

function collectSigner(value: string, previous: string[]): string[] {
  previous.push(value);
  return previous;
}

function buildEnrollmentObject({
  policy,
  signers,
  threshold,
  maxAge,
  casUrl,
}: EnrollmentOptions): EnrollmentInput {
  if (signers.length === 0) {
    throw new Error("at least one signer must be provided");
  }

  const normalized = signers.map(parseSignerKey);
  const unique = Array.from(new Set(normalized));
  if (unique.length !== normalized.length) {
    throw new Error("duplicate signer keys detected");
  }

  const parsedThreshold = parseInteger(threshold, "threshold");
  if (parsedThreshold === 0) {
    throw new Error("threshold must be at least 1");
  }
  if (parsedThreshold > unique.length) {
    throw new Error("threshold cannot exceed number of signers");
  }

  const parsedMaxAge = parseInteger(maxAge, "max-age");
  validateMaxAge(parsedMaxAge);
  validateCasUrl(casUrl);

  return {
    policy,
    signers: unique,
    threshold: parsedThreshold,
    max_age: parsedMaxAge,
    cas_url: casUrl,
  };
}

function parseEnrollmentObject(parsed: any): EnrollmentInput {
  if (typeof parsed.policy !== "string" || parsed.policy.length === 0) {
    throw new Error("enrollment.policy must be a base64url string");
  }
  if (!Array.isArray(parsed.signers)) {
    throw new Error("enrollment.signers must be an array");
  }
  if (parsed.signers.some((s: any) => typeof s !== "string" || s.length === 0)) {
    throw new Error("each signer must be a non-empty string");
  }
  const unique = new Set(parsed.signers);
  if (unique.size !== parsed.signers.length) {
    throw new Error("duplicate signer keys detected in enrollment");
  }

  const threshold = parseInteger(parsed.threshold, "threshold");
  if (threshold === 0) {
    throw new Error("threshold must be at least 1");
  }
  if (threshold > parsed.signers.length) {
    throw new Error("threshold cannot exceed number of signers");
  }

  const maxAge = parseInteger(parsed.max_age, "max-age");
  validateMaxAge(maxAge);
  validateCasUrl(parsed.cas_url);

  return parsed as EnrollmentInput;
}

async function loadEnrollment(path: string): Promise<EnrollmentInput> {
  const raw = await readFile(path, "utf8");
  let parsed: any;

  try {
    parsed = JSON.parse(raw);
  } catch (err: any) {
    throw new Error(`failed to parse enrollment JSON: ${err.message}`);
  }

  return parseEnrollmentObject(parsed);
}

async function writeMaybe(filePath: string | undefined, contents: string): Promise<void> {
  if (filePath) {
    await writeFile(filePath, contents);
  } else {
    process.stdout.write(contents + "\n");
  }
}

function ensureNonEmptyString(value: any, name: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${name} must be a non-empty string`);
  }
  return value.trim();
}

function ensureAbsolutePath(value: any, name: string): string {
  const normalized = ensureNonEmptyString(value, name);
  if (!normalized.startsWith("/")) {
    throw new Error(`${name} must start with '/'`);
  }
  return normalized;
}

function ensureRecordOfStrings(value: any, name: string): Record<string, string> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  const record: Record<string, string> = {};
  for (const [key, raw] of Object.entries(value)) {
    if (typeof raw !== "string" || raw.trim().length === 0) {
      throw new Error(`${name} entries must be non-empty strings`);
    }
    record[key] = raw.trim();
  }
  return record;
}

function runSigsumKeyToHex(pubKeyPath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      "sigsum-key",
      ["to-hex", "-k", pubKeyPath],
      { stdio: ["ignore", "pipe", "pipe"] } // capture stdout
    );

    let output = "";
    let errout = "";

    child.stdout.on("data", (d) => output += d.toString());
    child.stderr.on("data", (d) => errout += d.toString());

    child.on("error", (err) => {
      reject(new Error(`failed to launch sigsum-key: ${err.message}`));
    });

    child.on("exit", (code, signal) => {
      if (code === 0) {
        resolve(output.trim());
      } else if (signal) {
        reject(new Error(`sigsum-key terminated via signal ${signal}`));
      } else {
        reject(new Error(`sigsum-key exited with code ${code}: ${errout.trim()}`));
      }
    });
  });
}

function hexToBase64Url(hex: string): string {
  const buf = Buffer.from(hex, "hex");
  return buf.toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

async function deriveSignerKeyFromPrivateKey(privKeyPath: string): Promise<string> {
  const pubPath = `${privKeyPath}.pub`;

  const hex = await runSigsumKeyToHex(pubPath);

  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`sigsum-key returned invalid hex for ${pubPath}: ${hex}`);
  }

  return hexToBase64Url(hex);
}


async function loadManifestConfig(configPath: string): Promise<ManifestConfig> {
  const raw = await readFile(configPath, "utf8");
  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch (err: any) {
    throw new Error(`failed to parse manifest config JSON: ${err.message}`);
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("manifest config must be a JSON object");
  }

  const app = ensureNonEmptyString(parsed.app, "config.app");
  try {
    new URL(app);
  } catch (err: any) {
    throw new Error(`config.app must be a valid URL: ${err.message}`);
  }

  const version = ensureNonEmptyString(parsed.version, "config.version");
  const defaultCsp = ensureNonEmptyString(parsed.default_csp, "config.default_csp");
  // Remove leading / to default_index. It is automatically appended to dirs whcih
  // have a ending /
  let defaultIndex = ensureNonEmptyString(parsed.default_index, "config.default_index");
  defaultIndex = defaultIndex.replace(/^\/+/, ""); // optional: normalize if user wrote "/index.html"
  const defaultFallback = ensureAbsolutePath(parsed.default_fallback, "config.default_fallback");

  let wasmList: string[] = [];
  if (parsed.wasm === undefined) {
    wasmList = [];
  } else if (!Array.isArray(parsed.wasm)) {
    throw new Error("config.wasm must be an array of strings");
  } else {
    wasmList = parsed.wasm.map((value: any, index: number) => {
      if (typeof value !== "string" || value.trim().length === 0) {
        throw new Error(`config.wasm[${index}] must be a non-empty string`);
      }
      return value.trim();
    });
  }

  const extraCspRaw = parsed.extra_csp ?? {};
  const extraCspRecord = ensureRecordOfStrings(extraCspRaw, "config.extra_csp");
  for (const key of Object.keys(extraCspRecord)) {
    if (!key.startsWith("/")) {
      throw new Error(`config.extra_csp keys must start with '/': ${key}`);
    }
  }

  return {
    app,
    version,
    default_csp: defaultCsp,
    default_index: defaultIndex,
    default_fallback: defaultFallback,
    wasm: wasmList,
    extra_csp: extraCspRecord,
  };
}

async function scanDirectory(rootDir: string): Promise<DirectoryScanResult> {
  const absoluteRoot = path.resolve(rootDir);
  const result: DirectoryScanResult = {
    files: new Map(),
    wasm: new Set(),
  };

  async function walk(currentDir: string, relativePrefix: string): Promise<void> {
    const entries = await readdir(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const entryPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        const nextPrefix = relativePrefix ? `${relativePrefix}/${entry.name}` : entry.name;
        await walk(entryPath, nextPrefix);
        continue;
      }
      if (!entry.isFile()) {
        continue;
      }
      const relativePath = relativePrefix ? `${relativePrefix}/${entry.name}` : entry.name;
      const manifestPath = `/${relativePath}`;
      const contents = await readFile(entryPath);
      const digest = createHash("sha256").update(contents).digest();
      const encoded = toBase64Url(digest);
      if (path.extname(entry.name).toLowerCase() === WASM_EXTENSION) {
        result.wasm.add(encoded);
      } else {
        result.files.set(manifestPath, encoded);
      }
    }
  }

  await walk(absoluteRoot, "");
  return result;
}

function parseManifestDocumentObject(parsed: any): ManifestDocument {
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("manifest file must contain a JSON object");
  }
  if (typeof parsed.manifest !== "object" || parsed.manifest === null || Array.isArray(parsed.manifest)) {
    throw new Error("manifest file must include a 'manifest' object");
  }
  if (typeof parsed.signatures !== "object" || parsed.signatures === null || Array.isArray(parsed.signatures)) {
    parsed.signatures = {};
  }
  const manifest = parsed.manifest;
  if (typeof manifest.files !== "object" || manifest.files === null || Array.isArray(manifest.files)) {
    throw new Error("manifest.manifest.files must be an object");
  }
  if (manifest.wasm === undefined) {
    manifest.wasm = [];
  } else if (!Array.isArray(manifest.wasm)) {
    throw new Error("manifest.manifest.wasm must be an array");
  }
  if (manifest.extra_csp === undefined) {
    manifest.extra_csp = {};
  } else if (typeof manifest.extra_csp !== "object" || manifest.extra_csp === null || Array.isArray(manifest.extra_csp)) {
    throw new Error("manifest.manifest.extra_csp must be an object");
  }
  if (typeof manifest.timestamp !== "string" || manifest.timestamp.length === 0) {
    throw new Error("manifest.manifest.timestamp must be a string");
  }
  return parsed as ManifestDocument;
}

async function loadManifestDocument(manifestPath: string): Promise<ManifestDocument> {
  const raw = await readFile(manifestPath, "utf8");
  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch (err: any) {
    throw new Error(`failed to parse manifest JSON: ${err.message}`);
  }
  return parseManifestDocumentObject(parsed);
}

function canonicalizeManifestBody(document: ManifestDocument): string {
  return canonicalize(document.manifest);
}

function decodePolicyBytes(encoded: string): Uint8Array {
  try {
    const buffer = Buffer.from(encoded, "base64url");
    if (buffer.length === 0) {
      throw new Error("policy payload was empty");
    }
    return new Uint8Array(buffer);
  } catch (err: any) {
    throw new Error(`failed to decode compiled policy: ${err.message}`);
  }
}

function normalizeProofText(proofText: string): string {
  const versionMatch = proofText.match(/version=(\d+)/);
  if (versionMatch?.[1] === "2" && !/\btree_size=/.test(proofText)) {
    return proofText.replace(/(^|\n)size=/g, "$1tree_size=");
  }
  return proofText;
}

async function loadBundleDocument(bundlePath: string): Promise<{
  enrollment: EnrollmentInput;
  manifest: ManifestDocument;
}> {
  const raw = await readFile(bundlePath, "utf8");
  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch (err: any) {
    throw new Error(`failed to parse bundle JSON: ${err.message}`);
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("bundle file must contain a JSON object");
  }
  if (!parsed.enrollment) {
    throw new Error("bundle is missing 'enrollment'");
  }
  if (!parsed.manifest) {
    throw new Error("bundle is missing 'manifest'");
  }
  if (!parsed.signatures) {
    throw new Error("bundle is missing 'signatures'");
  }
  const enrollment = parseEnrollmentObject(parsed.enrollment);
  const manifest = parseManifestDocumentObject({
    manifest: parsed.manifest,
    signatures: parsed.signatures,
  });
  return { enrollment, manifest };
}

async function runSigsumSubmit(policyPath: string, keyPath: string, payloadPath: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const child = spawn("sigsum-submit", ["-p", policyPath, "-k", keyPath, payloadPath], {
      stdio: "inherit",
    });
    child.on("error", (err) => {
      reject(new Error(`failed to launch sigsum-submit: ${err.message}`));
    });
    child.on("exit", (code, signal) => {
      if (code === 0) {
        resolve();
        return;
      }
      if (signal) {
        reject(new Error(`sigsum-submit terminated via signal ${signal}`));
      } else {
        reject(new Error(`sigsum-submit exited with code ${code ?? 1}`));
      }
    });
  });
}

function parseCosignedTreeHead(text: string) {
  const signedTreeHead: any = {};
  const treeHead: any = {};
  const cosignatures = new Map<Base64KeyHash, { Timestamp: number; Signature: Signature }>();
  const lines = text.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line.length === 0) {
      continue;
    }
    if (line.startsWith("cosignature=")) {
      const [, rest] = line.split("=", 2);
      const parts = rest.trim().split(/\s+/);
      if (parts.length !== 3) {
        throw new Error("invalid cosignature format in timestamp");
      }
      const [keyHashHex, timestampStr, signatureHex] = parts;
      const timestamp = Number(timestampStr);
      if (!Number.isFinite(timestamp) || timestamp <= 0) {
        throw new Error("invalid cosignature timestamp");
      }
      const signature = new Signature(hexToUint8Array(signatureHex));
      cosignatures.set(new Base64KeyHash(hexToBase64(keyHashHex)), {
        Timestamp: timestamp,
        Signature: signature,
      });
      continue;
    }
    const [key, value] = line.split("=");
    if (!key || value === undefined) {
      continue;
    }
    if (key === "size" || key === "tree_size") {
      const size = Number(value);
      if (!Number.isFinite(size) || size <= 0) {
        throw new Error("invalid tree size in timestamp");
      }
      treeHead.Size = size;
      continue;
    }
    if (key === "root_hash") {
      treeHead.RootHash = new Hash(hexToUint8Array(value));
      continue;
    }
    if (key === "signature") {
      signedTreeHead.Signature = new Signature(hexToUint8Array(value));
      continue;
    }
  }
  if (!treeHead.Size || !treeHead.RootHash) {
    throw new Error("timestamp missing tree head fields");
  }
  if (!signedTreeHead.Signature) {
    throw new Error("timestamp missing log signature");
  }
  signedTreeHead.TreeHead = treeHead;
  return {
    SignedTreeHead: signedTreeHead,
    Cosignatures: cosignatures,
  };
}

async function fetchTimestampFromPolicy(policyText: string): Promise<string> {
  const policy = await parsePolicyText(policyText);
  const availableLogs = Array.from(policy.logs.entries()).filter(([, entity]) => typeof entity.url === "string" && entity.url.length > 0);
  if (availableLogs.length === 0) {
    throw new Error("policy does not list any logs with URLs for timestamp retrieval");
  }
  const selected = availableLogs[Math.floor(Math.random() * availableLogs.length)];
  const [, logEntity] = selected;
  const baseUrl = (logEntity.url as string).replace(/\/+$/, "");
  const requestUrl = `${baseUrl}/get-tree-head`;
  let response: Response;
  try {
    response = await fetch(requestUrl);
  } catch (err: any) {
    throw new Error(`failed to fetch timestamp from ${requestUrl}: ${err.message}`);
  }
  if (!response.ok) {
    throw new Error(`timestamp request failed (${response.status} ${response.statusText})`);
  }
  const body = await response.text();
  const trimmed = body.trim();
  const treeHead = parseCosignedTreeHead(trimmed);
  const logKeyHash = await hashKey(logEntity.publicKey);
  if (!(await verifySignedTreeHead(treeHead.SignedTreeHead, logEntity.publicKey, logKeyHash))) {
    throw new Error("timestamp tree head signature is invalid");
  }
  const present = new Set<Base64KeyHash>();
  for (const [keyHash, entity] of policy.witnesses) {
    const cosig = Base64KeyHash.lookup(treeHead.Cosignatures, keyHash);
    if (!cosig) {
      continue;
    }
    if (await verifyCosignedTreeHead(treeHead.SignedTreeHead.TreeHead, entity.publicKey, logKeyHash, cosig)) {
      present.add(keyHash);
      if (policy.quorum.isQuorum(present)) {
        return trimmed;
      }
    }
  }
  throw new Error("timestamp does not satisfy witness quorum");
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
  .requiredOption("-i, --input <path>", "Enrollment file to canonicalize")
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
  .requiredOption("-i, --input <path>", "Manifest file to hash")
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
    "<enrollment-or-bundle>",
    "Path to an enrollment JSON file or to a bundle JSON file",
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
      const policyHash = createHash("sha256")
        .update(compiledPolicy)
        .digest("base64url");

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
          const normalizedProof = normalizeProofText(proofText);
          const ok = await verifyHashWithCompiledPolicy(
            manifestHash,
            signerKey,
            compiledPolicy,
            normalizedProof,
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


program.parseAsync(process.argv).catch((err: any) => {
  process.stderr.write(`Error: ${err.message}\n`);
  process.exit(1);
});
