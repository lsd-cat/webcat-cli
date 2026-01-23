import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { Updater } from "tuf-js";

const SIGSTORE_TUF_BASE_URL = "https://tuf-repo.sigstore.dev";
const SIGSTORE_TRUSTED_ROOT_TARGET = "trusted_root.json";

export async function fetchCommunityTrustedRoot(): Promise<string> {
  const tempDir = await mkdtemp(path.join(tmpdir(), "webcat-tuf-"));
  const metadataDir = path.join(tempDir, "metadata");
  const targetDir = path.join(tempDir, "targets");

  try {
    await Promise.all([
      mkdir(metadataDir, { recursive: true }),
      mkdir(targetDir, { recursive: true }),
    ]);

    const rootResponse = await fetch(`${SIGSTORE_TUF_BASE_URL}/root.json`);
    if (!rootResponse.ok) {
      throw new Error(
        `failed to download sigstore TUF root.json (${rootResponse.status} ${rootResponse.statusText})`
      );
    }
    const rootBytes = Buffer.from(await rootResponse.arrayBuffer());
    await writeFile(path.join(metadataDir, "root.json"), rootBytes);

    const updater = new Updater({
      metadataDir,
      metadataBaseUrl: SIGSTORE_TUF_BASE_URL,
      targetDir,
      targetBaseUrl: `${SIGSTORE_TUF_BASE_URL}/targets`,
    });

    const targetInfo = await updater.getTargetInfo(SIGSTORE_TRUSTED_ROOT_TARGET);
    if (!targetInfo) {
      throw new Error("sigstore trusted_root.json target not found in TUF metadata");
    }

    const targetPath = await updater.downloadTarget(targetInfo);
    return await readFile(targetPath, "utf8");
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}
