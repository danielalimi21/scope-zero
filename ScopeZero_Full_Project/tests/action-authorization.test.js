import test from "node:test";
import assert from "node:assert/strict";
import { describeActionRequest, evaluateActionContract } from "../src/actionAuthorization.js";

test("action descriptor classifies external send and sensitive destination", () => {
  const descriptor = describeActionRequest(
    {
      tool: "gmail.send",
      action: "Send raw customer revenue externally",
      operation: "external_send",
      destination: {
        type: "email",
        address: "outside@example.com",
        external: true
      }
    },
    { label: "restricted" }
  );

  assert.equal(descriptor.action_type, "external_send");
  assert.equal(descriptor.vendor, "gmail");
  assert.equal(descriptor.data_rank, 5);
  assert.equal(descriptor.destination.external, true);
});

test("mission action contract rejects tools outside the signed contract", () => {
  const action = describeActionRequest(
    {
      tool: "sheets.export",
      action: "Export revenue sheet",
      operation: "export"
    },
    { label: "restricted" }
  );
  const result = evaluateActionContract({
    mission: {
      action_contracts: [
        {
          id: "safe-summary",
          tools: ["slack.draft"],
          operations: ["draft"],
          data_classes: ["public", "internal"],
          destinations: ["diligence-room.contoso.example"]
        }
      ]
    },
    action,
    externalDestination: false
  });

  assert.equal(result.ok, false);
  assert.equal(result.code, "tool-not-contracted");
});
