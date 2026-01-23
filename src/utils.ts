import { createHash } from "node:crypto";

const WEEK_SECONDS = 7 * 24 * 60 * 60;
const YEAR_SECONDS = 365 * 24 * 60 * 60;
const HEX_RE = /^[0-9a-fA-F]+$/;

export function toBase64Url(input: Uint8Array | Buffer): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function decodeKeyMaterial(value: string, name: string): Buffer {
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

export function parseInteger(value: number | string, name: string): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(n) || n < 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return n;
}

export function validateMaxAge(maxAge: number): void {
  if (maxAge <= WEEK_SECONDS) {
    throw new Error("max-age must be larger than one week");
  }
  if (maxAge >= YEAR_SECONDS) {
    throw new Error("max-age must be smaller than one year");
  }
}

export function validateCasUrl(urlString: string): void {
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

export function ensureNonEmptyString(value: any, name: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${name} must be a non-empty string`);
  }
  return value.trim();
}

export function ensureObject(value: any, name: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

export function ensureAbsolutePath(value: any, name: string): string {
  const normalized = ensureNonEmptyString(value, name);
  if (!normalized.startsWith("/")) {
    throw new Error(`${name} must start with '/'`);
  }
  return normalized;
}

export function ensureRecordOfStrings(value: any, name: string): Record<string, string> {
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

export function hexToBase64Url(hex: string): string {
  const buf = Buffer.from(hex, "hex");
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function decodePolicyBytes(encoded: string): Uint8Array {
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

export function hashPolicyBytes(encodedPolicy: string): string {
  return createHash("sha256").update(decodePolicyBytes(encodedPolicy)).digest("base64url");
}
