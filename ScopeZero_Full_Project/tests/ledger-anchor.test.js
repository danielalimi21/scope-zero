import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Ledger } from "../src/ledger.js";
import { LedgerAnchor } from "../src/ledgerAnchor.js";

test("ledger anchor writes signed chain roots outside the primary ledger", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "scopezero-ledger-anchor-"));
  const ledgerPath = path.join(dir, "ledger.jsonl");
  const anchorPath = path.join(dir, "anchors.jsonl");
  const ledger = new Ledger(ledgerPath, {
    anchor: new LedgerAnchor({
      filePath: anchorPath,
      secret: "anchor-secret"
    })
  });

  await ledger.init();
  const entry = await ledger.append({
    event_type: "action_authorization.evaluated",
    tenant_id: "tenant_contoso",
    verdict: { decision: "allow" }
  });

  const anchors = (await readFile(anchorPath, "utf8")).trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(anchors.length, 1);
  assert.equal(anchors[0].event_id, entry.id);
  assert.equal(anchors[0].chain_root, entry.hash);
  assert.equal(anchors[0].tenant_id, "tenant_contoso");
  assert.equal(typeof anchors[0].signature, "string");
});

test("ledger anchor can post chain roots to an external witness endpoint", async () => {
  const posted = [];
  const anchor = new LedgerAnchor({
    url: "https://anchor.example/scopezero",
    secret: "anchor-secret",
    fetchImpl: async (url, options) => {
      posted.push({ url, options });
      return { ok: true, status: 201 };
    }
  });

  const result = await anchor.record({
    id: "evt_test",
    time: "2026-05-29T00:00:00.000Z",
    previous_hash: "prev",
    hash: "root",
    record: {
      event_type: "mission.issued",
      tenant_id: "tenant_contoso"
    }
  });

  assert.equal(result.chain_root, "root");
  assert.equal(posted.length, 1);
  assert.equal(posted[0].url, "https://anchor.example/scopezero");
  assert.equal(JSON.parse(posted[0].options.body).chain_root, "root");
});
