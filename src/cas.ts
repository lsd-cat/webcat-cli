import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";

export interface CasWriteResult {
  hash: string;
  filePath: string;
}

interface CasUploadConfig {
  endpoint: string;
  bucket: string;
  token: string;
  region: string;
}

const casUploadConfig = loadCasUploadConfig();
let casS3Client: S3Client | null = null;

function loadCasUploadConfig(): CasUploadConfig | null {
  const endpoint = process.env.WEBCAT_CAS_S3_ENDPOINT;
  const bucket = process.env.WEBCAT_CAS_S3_BUCKET;
  const token = process.env.WEBCAT_CAS_S3_TOKEN;
  if (!endpoint && !bucket && !token) {
    return null;
  }
  const missing = [];
  if (!endpoint) {
    missing.push("WEBCAT_CAS_S3_ENDPOINT");
  }
  if (!bucket) {
    missing.push("WEBCAT_CAS_S3_BUCKET");
  }
  if (!token) {
    missing.push("WEBCAT_CAS_S3_TOKEN");
  }
  if (missing.length > 0) {
    throw new Error(`missing CAS upload environment variables: ${missing.join(", ")}`);
  }
  return {
    endpoint,
    bucket,
    token,
    region: process.env.WEBCAT_CAS_S3_REGION ?? "us-east-1",
  };
}

async function uploadCasObject(hash: string, bytes: Uint8Array): Promise<void> {
  if (!casUploadConfig) {
    return;
  }
  if (!casS3Client) {
    casS3Client = new S3Client({
      endpoint: casUploadConfig.endpoint,
      region: casUploadConfig.region,
      credentials: {
        accessKeyId: casUploadConfig.token,
        secretAccessKey: casUploadConfig.token,
      },
      forcePathStyle: true,
    });
  }
  await casS3Client.send(
    new PutObjectCommand({
      Bucket: casUploadConfig.bucket,
      Key: hash,
      Body: bytes,
    })
  );
}

export async function writeCasObject(
  data: Uint8Array | string,
  options?: { upload?: boolean }
): Promise<CasWriteResult> {
  const bytes = typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data);
  const hash = createHash("sha256").update(bytes).digest("hex");
  const casDir = path.join(process.cwd(), "cas");
  await mkdir(casDir, { recursive: true });
  const filePath = path.join(casDir, hash);
  await writeFile(filePath, bytes);
  if (options?.upload) {
    await uploadCasObject(hash, bytes);
  }
  return { hash, filePath };
}
