import { readFile } from "node:fs/promises";
import {
  decodeKeyMaterial,
  ensureRecordOfStrings,
  parseInteger,
  toBase64Url,
  validateCasUrl,
  validateMaxAge,
} from "./utils";

export interface EnrollmentInput {
  policy: string;
  signers: string[];
  threshold: number;
  max_age: number;
  cas_url: string;
  logs?: Record<string, string>;
}

export interface EnrollmentOptions {
  policy: string;
  signers: string[];
  threshold: number | string;
  maxAge: number | string;
  casUrl: string;
  logs?: Record<string, string>;
}

export function parseSignerKey(value: string): string {
  return toBase64Url(decodeKeyMaterial(value, "signer keys"));
}

export function buildEnrollmentObject({
  policy,
  signers,
  threshold,
  maxAge,
  casUrl,
  logs,
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

  const normalizedLogs = logs ? ensureRecordOfStrings(logs, "logs") : undefined;

  return {
    policy,
    signers: unique,
    threshold: parsedThreshold,
    max_age: parsedMaxAge,
    cas_url: casUrl,
    ...(normalizedLogs ? { logs: normalizedLogs } : {}),
  };
}

export function parseEnrollmentObject(parsed: any): EnrollmentInput {
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

  if (parsed.logs !== undefined) {
    ensureRecordOfStrings(parsed.logs, "enrollment.logs");
  }

  return parsed as EnrollmentInput;
}

export async function loadEnrollment(path: string): Promise<EnrollmentInput> {
  const raw = await readFile(path, "utf8");
  let parsed: any;

  try {
    parsed = JSON.parse(raw);
  } catch (err: any) {
    throw new Error(`failed to parse enrollment JSON: ${err.message}`);
  }

  return parseEnrollmentObject(parsed);
}
