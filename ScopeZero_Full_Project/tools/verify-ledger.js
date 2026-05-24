import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRuntime } from "../src/runtime.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const runtime = await createRuntime({
  rootDir,
  signingSecret: process.env.SCOPEZERO_SIGNING_SECRET || "dev-scopezero-signing-secret-change-me"
});

const result = await runtime.verifyLedger();
console.log(JSON.stringify(result, null, 2));
if (!result.valid) {
  process.exit(1);
}
