import test from "node:test";
import assert from "node:assert/strict";
import { describeActionRequest } from "../src/actionAuthorization.js";
import { evaluateMissionAlignment } from "../src/missionAlignment.js";

test("server-side mission alignment allows matching internal diligence summary", () => {
  const action = describeActionRequest(
    {
      tool: "slack.draft",
      action: "Draft diligence summary for the approved room",
      destination: { type: "slack", address: "diligence-room.contoso.example" }
    },
    { label: "internal" }
  );

  const result = evaluateMissionAlignment({
    mission: { objective: "Read diligence documents and draft an internal diligence summary for the approved room." },
    action,
    request: { payload: { summary: "Internal diligence summary." } }
  });

  assert.equal(result.aligned, true);
  assert.equal(result.source, "server_deterministic");
});

test("server-side mission alignment rejects external send when objective never authorizes sharing", () => {
  const action = describeActionRequest(
    {
      tool: "gmail.send",
      action: "Send raw revenue table to outside advisor",
      destination: { type: "email", address: "advisor@example.com", external: true }
    },
    { label: "restricted" }
  );

  const result = evaluateMissionAlignment({
    mission: { objective: "Read internal diligence documents and prepare an internal summary." },
    action,
    request: { payload: { text: "Restricted revenue table." } }
  });

  assert.equal(result.aligned, false);
  assert.ok(result.reasons.includes("external-destination-not-in-objective"));
});
