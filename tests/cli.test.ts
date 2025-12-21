import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import {
  buildEnrollmentObject,
  decodeKeyMaterial,
  ensureAbsolutePath,
  ensureNonEmptyString,
  ensureRecordOfStrings,
  hexToBase64Url,
  loadBundleDocument,
  loadEnrollment,
  loadManifestConfig,
  loadManifestDocument,
  parseEnrollmentObject,
  parseInteger,
  parseManifestDocumentObject,
  parseSignerKey,
  scanDirectory,
  toBase64Url,
  validateCasUrl,
  validateMaxAge,
} from "../src/test-exports";

describe("key parsing", () => {
  it("decodes hex and base64url strings", () => {
    const hexInput = "11".repeat(32);
    const hexResult = decodeKeyMaterial(hexInput, "test");
    expect(hexResult).toHaveLength(32);

    const base64Buffer = Buffer.alloc(32, 0xff);
    const base64Input = toBase64Url(base64Buffer);
    const base64Result = decodeKeyMaterial(base64Input, "test");
    expect(base64Result.equals(base64Buffer)).toBe(true);
  });

  it("rejects malformed key material", () => {
    expect(() => decodeKeyMaterial("abc", "key")).toThrow(
      "key must contain an even number of hex characters",
    );
    expect(() => decodeKeyMaterial("not_base64", "key")).toThrow(
      /key must be 32 bytes/,
    );
    expect(() => decodeKeyMaterial("00".repeat(8), "key")).toThrow(
      "key must be 32 bytes",
    );
  });

  it("parses signer keys and normalizes hex", () => {
    const hexInput = "11".repeat(32);
    const expected = hexToBase64Url(hexInput);
    expect(parseSignerKey(hexInput)).toBe(expected);
  });
});

describe("integer and range validation", () => {
  it("enforces positive integers", () => {
    expect(() => parseInteger(-1, "value")).toThrow("value must be a positive integer");
    expect(() => parseInteger("oops", "value")).toThrow("value must be a positive integer");
    expect(parseInteger(5, "value")).toBe(5);
  });

  it("enforces max-age bounds", () => {
    expect(() => validateMaxAge(60 * 60 * 24 * 7)).toThrow(
      "max-age must be larger than one week",
    );
    expect(() => validateMaxAge(60 * 60 * 24 * 365)).toThrow(
      "max-age must be smaller than one year",
    );
    expect(() => validateMaxAge(60 * 60 * 24 * 30)).not.toThrow();
  });

  it("validates CAS URLs", () => {
    expect(() => validateCasUrl("notaurl")).toThrow("invalid CAS URL");
    expect(() => validateCasUrl("http://example.com")).toThrow("CAS URL must use https://");
    expect(() => validateCasUrl("https://")).toThrow("invalid CAS URL");
    expect(() => validateCasUrl("https://example.com")).not.toThrow();
  });
});

describe("enrollment helpers", () => {
  const baseSigner = "aa".repeat(32);
  const secondSigner = "bb".repeat(32);

  it("builds normalized enrollment objects", () => {
    const enrollment = buildEnrollmentObject({
      policy: "policy-bytes",
      signers: [baseSigner],
      threshold: 1,
      maxAge: 1_000_000,
      casUrl: "https://example.com",
    });

    expect(enrollment.signers).toEqual([hexToBase64Url(baseSigner)]);
    expect(enrollment.threshold).toBe(1);
    expect(enrollment.max_age).toBe(1_000_000);
  });

  it("rejects duplicate or insufficient signer information", () => {
    expect(() =>
      buildEnrollmentObject({
        policy: "policy",
        signers: [],
        threshold: 1,
        maxAge: 1_000_000,
        casUrl: "https://example.com",
      }),
    ).toThrow("at least one signer must be provided");

    expect(() =>
      buildEnrollmentObject({
        policy: "policy",
        signers: [baseSigner, baseSigner],
        threshold: 1,
        maxAge: 1_000_000,
        casUrl: "https://example.com",
      }),
    ).toThrow("duplicate signer keys detected");

    expect(() =>
      buildEnrollmentObject({
        policy: "policy",
        signers: [baseSigner, secondSigner],
        threshold: 3,
        maxAge: 1_000_000,
        casUrl: "https://example.com",
      }),
    ).toThrow("threshold cannot exceed number of signers");

    expect(() =>
      buildEnrollmentObject({
        policy: "policy",
        signers: [baseSigner],
        threshold: 0,
        maxAge: 1_000_000,
        casUrl: "https://example.com",
      }),
    ).toThrow("threshold must be at least 1");

    expect(() =>
      buildEnrollmentObject({
        policy: "policy",
        signers: [baseSigner],
        threshold: 1,
        maxAge: 60 * 60 * 24 * 8,
        casUrl: "http://example.com",
      }),
    ).toThrow("CAS URL must use https://");
  });

  it("parses enrollment JSON files", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "webcat-enroll-"));
    const file = path.join(dir, "enrollment.json");
    await writeFile(
      file,
      JSON.stringify({
        policy: "policy",
        signers: [hexToBase64Url(baseSigner)],
        threshold: 1,
        max_age: 1_000_000,
        cas_url: "https://example.com",
      }),
    );

    const loaded = await loadEnrollment(file);
    expect(loaded.signers).toEqual([hexToBase64Url(baseSigner)]);

    await writeFile(file, "not json");
    await expect(loadEnrollment(file)).rejects.toThrow("failed to parse enrollment JSON");

    await rm(dir, { recursive: true, force: true });
  });

  it("parses enrollment objects with validation", () => {
    expect(() =>
      parseEnrollmentObject({
        policy: "",
        signers: ["x"],
        threshold: 1,
        max_age: 1,
        cas_url: "https://example.com",
      }),
    ).toThrow("enrollment.policy must be a base64url string");

    expect(() =>
      parseEnrollmentObject({
        policy: "policy",
        signers: ["a", "a"],
        threshold: 1,
        max_age: 1,
        cas_url: "https://example.com",
      }),
    ).toThrow("duplicate signer keys detected in enrollment");
  });
});

describe("string and path validation", () => {
  it("ensures non-empty strings", () => {
    expect(() => ensureNonEmptyString("", "field")).toThrow("field must be a non-empty string");
    expect(ensureNonEmptyString(" value ", "field")).toBe("value");
  });

  it("ensures absolute paths", () => {
    expect(() => ensureAbsolutePath("relative", "p")).toThrow("p must start with '/'");
    expect(ensureAbsolutePath("/absolute", "p")).toBe("/absolute");
  });

  it("ensures records of strings", () => {
    expect(() => ensureRecordOfStrings([], "record")).toThrow("record must be an object");
    expect(() => ensureRecordOfStrings({ key: "" }, "record")).toThrow(
      "record entries must be non-empty strings",
    );
    expect(ensureRecordOfStrings({ a: "x" }, "record")).toEqual({ a: "x" });
  });
});

describe("manifest configuration", () => {
  it("loads and normalizes configuration", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "webcat-config-"));
    const configPath = path.join(dir, "config.json");
    await writeFile(
      configPath,
      JSON.stringify({
        app: "https://example.com",
        version: "1.0.0",
        default_csp: "default-src 'none'",
        default_index: "/index.html",
        default_fallback: "/error.html",
        wasm: ["module.wasm"],
        extra_csp: { "/path": "policy" },
      }),
    );

    const config = await loadManifestConfig(configPath);
    expect(config.default_index).toBe("index.html");
    expect(config.extra_csp["/path"]).toBe("policy");

    await writeFile(configPath, "not json");
    await expect(loadManifestConfig(configPath)).rejects.toThrow(
      "failed to parse manifest config JSON",
    );

    await writeFile(
      configPath,
      JSON.stringify({
        app: "https://example.com",
        version: "1.0.0",
        default_csp: "csp",
        default_index: "index.html",
        default_fallback: "relative.html",
      }),
    );

    await expect(loadManifestConfig(configPath)).rejects.toThrow(
      "config.default_fallback must start with '/'",
    );

    await rm(dir, { recursive: true, force: true });
  });
});

describe("directory scanning", () => {
  it("hashes files and wasm artifacts", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "webcat-scan-"));
    await writeFile(path.join(dir, "index.html"), "hello");
    await writeFile(path.join(dir, "module.wasm"), "wasm-bytes");

    const result = await scanDirectory(dir);
    const indexHash = createHash("sha256").update("hello").digest();
    expect(result.files.get("/index.html")).toBe(toBase64Url(indexHash));
    const wasmHash = createHash("sha256").update("wasm-bytes").digest();
    expect(result.wasm.has(toBase64Url(wasmHash))).toBe(true);

    await rm(dir, { recursive: true, force: true });
  });
});

describe("manifest parsing", () => {
  it("validates manifest documents", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "webcat-manifest-"));
    const manifestPath = path.join(dir, "manifest.json");

    const manifest = {
      manifest: {
        files: {},
        wasm: [],
        extra_csp: {},
        timestamp: "2024-01-01T00:00:00Z",
        app: "app",
        version: "1",
        default_csp: "csp",
        default_index: "index.html",
        default_fallback: "/error.html",
      },
      signatures: {},
    };

    await writeFile(manifestPath, JSON.stringify(manifest));
    const loaded = await loadManifestDocument(manifestPath);
    expect(Object.keys(loaded.manifest.files)).toHaveLength(0);

    await writeFile(manifestPath, "{]");
    await expect(loadManifestDocument(manifestPath)).rejects.toThrow(
      "failed to parse manifest JSON",
    );

    expect(() => parseManifestDocumentObject({})).toThrow(
      "manifest file must include a 'manifest' object",
    );

    await rm(dir, { recursive: true, force: true });
  });
});

describe("policy and bundle parsing", () => {

  it("validates bundle documents", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "webcat-bundle-"));
    const bundlePath = path.join(dir, "bundle.json");
    await writeFile(
      bundlePath,
      JSON.stringify({
        enrollment: {
          policy: "policy",
          signers: [""],
          threshold: 1,
          max_age: 1_000_000,
          cas_url: "https://example.com",
        },
        manifest: {
          files: {},
          wasm: [],
          extra_csp: {},
          timestamp: "ts",
          app: "a",
          version: "1",
          default_csp: "csp",
          default_index: "index",
          default_fallback: "/error",
        },
        signatures: {},
      }),
    );

    await expect(loadBundleDocument(bundlePath)).rejects.toThrow(
      "each signer must be a non-empty string",
    );

    await writeFile(bundlePath, "{}");
    await expect(loadBundleDocument(bundlePath)).rejects.toThrow("bundle is missing 'enrollment'");

    await writeFile(
      bundlePath,
      JSON.stringify({
        enrollment: {
          policy: "policy",
          signers: ["abc"],
          threshold: 1,
          max_age: 1_000_000,
          cas_url: "https://example.com",
        },
        signatures: {},
      }),
    );

    await expect(loadBundleDocument(bundlePath)).rejects.toThrow("bundle is missing 'manifest'");

    await rm(dir, { recursive: true, force: true });
  });
});
