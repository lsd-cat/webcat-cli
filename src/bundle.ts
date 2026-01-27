import { readFile } from "node:fs/promises";
import { EnrollmentInput, parseEnrollmentObject } from "./enrollment";
import { ManifestDocument, parseManifestDocumentObject } from "./manifest";

export async function loadBundleDocument(bundlePath: string): Promise<{
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
