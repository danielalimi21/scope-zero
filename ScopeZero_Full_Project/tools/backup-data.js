import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const backupDir = path.join(rootDir, "backups", new Date().toISOString().replace(/[:.]/g, "-"));
await fs.mkdir(backupDir, { recursive: true });

for (const file of ["scopezero.db", "scopezero.db-wal", "scopezero.db-shm", "ledger.jsonl", "state.json"]) {
  const source = path.join(rootDir, "data", file);
  const target = path.join(backupDir, file);
  try {
    await fs.copyFile(source, target);
  } catch {
    // Some SQLite sidecar files may not exist depending on shutdown state.
  }
}

console.log(`Backup written to ${backupDir}`);
