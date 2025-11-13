#!/usr/bin/env node
import { Command } from "commander";
import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import process from "node:process";
import { compilePolicy } from "sigsum/dist/policyCompiler";
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

function toBase64Url(input: Uint8Array | Buffer): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function parseSignerKey(value: string): string {
  const trimmed = value.trim();
  let bytes: Buffer;

  if (HEX_RE.test(trimmed)) {
    if (trimmed.length % 2 !== 0) {
      throw new Error("hex-encoded signer keys must contain an even number of characters");
    }
    bytes = Buffer.from(trimmed, "hex");
  } else {
    const normalized = trimmed.replace(/-/g, "+").replace(/_/g, "/");
    try {
      bytes = Buffer.from(normalized, "base64");
    } catch (err: any) {
      throw new Error(`invalid base64 signer key: ${err.message}`);
    }
  }

  if (bytes.length !== 32) {
    throw new Error("signer keys must be 32 bytes (ed25519 public keys)");
  }

  return toBase64Url(bytes);
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

async function loadEnrollment(path: string): Promise<EnrollmentInput> {
  const raw = await readFile(path, "utf8");
  let parsed: any;

  try {
    parsed = JSON.parse(raw);
  } catch (err: any) {
    throw new Error(`failed to parse enrollment JSON: ${err.message}`);
  }

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

async function writeMaybe(filePath: string | undefined, contents: string): Promise<void> {
  if (filePath) {
    await writeFile(filePath, contents);
  } else {
    process.stdout.write(contents + "\n");
  }
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


program
  .command("manifest")
  .description("Manifest helpers (reserved)")
  .action(() => {
    throw new Error("manifest commands wip");
  });

program
  .command("bundle")
  .description("Bundle helpers (reserved)")
  .action(() => {
    throw new Error("bundle commands will wip");
  });


program.parseAsync(process.argv).catch((err: any) => {
  process.stderr.write(`Error: ${err.message}\n`);
  process.exit(1);
});
