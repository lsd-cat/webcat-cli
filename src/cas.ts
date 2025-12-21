import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

export interface CasWriteResult {
  hash: string;
  filePath: string;
}

export async function writeCasObject(data: Uint8Array | string): Promise<CasWriteResult> {
  const bytes = typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data);
  const hash = createHash("sha256").update(bytes).digest("hex");
  const casDir = path.join(process.cwd(), "cas");
  await mkdir(casDir, { recursive: true });
  const filePath = path.join(casDir, hash);
  await writeFile(filePath, bytes);
  return { hash, filePath };
}
