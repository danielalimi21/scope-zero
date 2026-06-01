import test from "node:test";
import assert from "node:assert/strict";
import { ConnectorRegistry } from "../src/connectors.js";

test("google connectors stay as stubs when credentials are absent", () => {
  const registry = new ConnectorRegistry({ env: {}, fetchImpl: unreachableFetch });
  const driveSearch = registry.list().find((c) => c.name === "drive.search");
  const driveRead = registry.list().find((c) => c.name === "drive.read");
  const gmailSend = registry.list().find((c) => c.name === "gmail.send");
  // Stubs exist but are not in google-api mode — no real API calls
  assert.notEqual(driveSearch.mode, "google-api");
  assert.notEqual(driveRead.mode, "google-api");
  assert.notEqual(gmailSend.mode, "google-api");
});

test("google connectors are registered when all credentials are present", () => {
  const registry = new ConnectorRegistry({
    env: {
      SCOPEZERO_GOOGLE_CLIENT_ID: "client-id",
      SCOPEZERO_GOOGLE_CLIENT_SECRET: "client-secret",
      SCOPEZERO_GOOGLE_REFRESH_TOKEN: "refresh-token"
    },
    fetchImpl: unreachableFetch
  });
  const names = registry.list().map((c) => c.name);
  assert.ok(names.includes("drive.search"), "drive.search should be registered");
  assert.ok(names.includes("drive.read"), "drive.read should be registered");
  assert.ok(names.includes("gmail.send"), "gmail.send should be registered");
});

test("drive.search returns file list from Google Drive API", async () => {
  const fakeFiles = [
    { id: "file1", name: "Q3 Report.docx", mimeType: "application/vnd.google-apps.document" },
    { id: "file2", name: "Budget.xlsx", mimeType: "application/vnd.ms-excel" }
  ];

  const registry = new ConnectorRegistry({
    env: {
      SCOPEZERO_GOOGLE_CLIENT_ID: "client-id",
      SCOPEZERO_GOOGLE_CLIENT_SECRET: "client-secret",
      SCOPEZERO_GOOGLE_REFRESH_TOKEN: "refresh-token"
    },
    fetchImpl: async (url, options) => {
      if (url === "https://oauth2.googleapis.com/token") {
        return jsonResponse({ access_token: "test-access-token", expires_in: 3600 });
      }
      if (url.startsWith("https://www.googleapis.com/drive/v3/files?")) {
        return jsonResponse({ files: fakeFiles });
      }
      return jsonResponse({ error: { message: `Unexpected: ${url}` } }, 500);
    }
  });

  const result = await registry.execute("drive.search", {
    tenant_id: "tenant_contoso",
    agent_id: "agent.test",
    mission_id: "mission_test",
    action: "Search Q3 files",
    payload: { query: "name contains 'Q3'" }
  }, { evidence_hash: "hash_test" });

  assert.equal(result.isError, false);
  assert.equal(result.structuredContent.mode, "google-api");
  assert.equal(result.structuredContent.files.length, 2);
  assert.equal(result.structuredContent.files[0].name, "Q3 Report.docx");
});

test("gmail.send sends email via Gmail API", async () => {
  const calls = [];
  const registry = new ConnectorRegistry({
    env: {
      SCOPEZERO_GOOGLE_CLIENT_ID: "client-id",
      SCOPEZERO_GOOGLE_CLIENT_SECRET: "client-secret",
      SCOPEZERO_GOOGLE_REFRESH_TOKEN: "refresh-token"
    },
    fetchImpl: async (url, options) => {
      calls.push({ url, method: options?.method });
      if (url === "https://oauth2.googleapis.com/token") {
        return jsonResponse({ access_token: "test-token", expires_in: 3600 });
      }
      if (url === "https://gmail.googleapis.com/gmail/v1/users/me/messages/send") {
        return jsonResponse({ id: "msg_abc123", labelIds: ["SENT"] });
      }
      return jsonResponse({ error: { message: `Unexpected: ${url}` } }, 500);
    }
  });

  const result = await registry.execute("gmail.send", {
    tenant_id: "tenant_contoso",
    agent_id: "agent.test",
    mission_id: "mission_test",
    action: "Send diligence summary",
    payload: {
      to: "security@contoso.example",
      subject: "Q3 Diligence Summary",
      body: "Please review the attached summary."
    }
  }, { evidence_hash: "hash_test" });

  assert.equal(result.isError, false);
  assert.equal(result.structuredContent.message_id, "msg_abc123");
  assert.equal(result.structuredContent.to, "security@contoso.example");
  assert.ok(calls.some((c) => c.url === "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"));
});

test("gmail.send fails when to address is missing", async () => {
  const registry = new ConnectorRegistry({
    env: {
      SCOPEZERO_GOOGLE_CLIENT_ID: "client-id",
      SCOPEZERO_GOOGLE_CLIENT_SECRET: "client-secret",
      SCOPEZERO_GOOGLE_REFRESH_TOKEN: "refresh-token"
    },
    fetchImpl: async (url) => {
      if (url === "https://oauth2.googleapis.com/token") {
        return jsonResponse({ access_token: "test-token", expires_in: 3600 });
      }
      throw new Error("unexpected fetch");
    }
  });

  const result = await registry.execute("gmail.send", {
    tenant_id: "tenant_contoso",
    agent_id: "agent.test",
    mission_id: "mission_test",
    action: "Send without recipient",
    payload: { subject: "Missing to field" }
  }, { evidence_hash: "hash_test" });

  assert.equal(result.isError, true);
  assert.ok(result.structuredContent.error.includes("payload.to is required"));
});

function jsonResponse(payload, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() { return payload; },
    async text() { return JSON.stringify(payload); },
    async arrayBuffer() { return Buffer.from(JSON.stringify(payload)); }
  };
}

async function unreachableFetch() {
  throw new Error("fetch should not be called");
}
