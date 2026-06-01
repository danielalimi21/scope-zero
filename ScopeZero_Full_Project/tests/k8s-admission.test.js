import test from "node:test";
import assert from "node:assert/strict";
import {
  handleValidateAdmission,
  handleMutateAdmission,
  generateNetworkPolicy,
  generateDefaultDenyEgressPolicy,
  generateMutatingWebhookConfig,
  generateValidatingWebhookConfig,
  generateFullEnforcementManifests
} from "../src/k8sAdmission.js";

const PROXY_URL = "http://scopezero:8788";

function makeAdmissionReview(containers, uid = "test-uid") {
  return {
    apiVersion: "admission.k8s.io/v1",
    kind: "AdmissionReview",
    request: {
      uid,
      object: {
        spec: { containers }
      }
    }
  };
}

function makeContainer(name, envOverrides = []) {
  return { name, env: envOverrides };
}

function proxyEnvs(proxyUrl = PROXY_URL) {
  return [
    { name: "HTTP_PROXY",  value: proxyUrl },
    { name: "HTTPS_PROXY", value: proxyUrl },
    { name: "http_proxy",  value: proxyUrl },
    { name: "https_proxy", value: proxyUrl },
    { name: "NO_PROXY",    value: "localhost,127.0.0.1" }
  ];
}

// ── Validating webhook ───────────────────────────────────────────────────────

test("validate: allows pod with correct proxy configured", () => {
  const review = makeAdmissionReview([makeContainer("agent", proxyEnvs())]);
  const result = handleValidateAdmission(review, PROXY_URL);
  assert.equal(result.response.allowed, true);
});

test("validate: denies pod with no proxy env", () => {
  const review = makeAdmissionReview([makeContainer("agent", [])]);
  const result = handleValidateAdmission(review, PROXY_URL);
  assert.equal(result.response.allowed, false);
  assert.ok(result.response.status.message.includes("agent"));
  assert.ok(result.response.status.message.includes(PROXY_URL));
});

test("validate: denies pod with wrong proxy URL", () => {
  const review = makeAdmissionReview([makeContainer("agent", [
    { name: "HTTP_PROXY", value: "http://some-other-proxy:3128" }
  ])]);
  const result = handleValidateAdmission(review, PROXY_URL);
  assert.equal(result.response.allowed, false);
});

test("validate: denies when any container lacks proxy even if others have it", () => {
  const review = makeAdmissionReview([
    makeContainer("agent-ok", proxyEnvs()),
    makeContainer("agent-bad", [])
  ]);
  const result = handleValidateAdmission(review, PROXY_URL);
  assert.equal(result.response.allowed, false);
  assert.ok(result.response.status.message.includes("agent-bad"));
});

test("validate: accepts lowercase http_proxy as valid", () => {
  const review = makeAdmissionReview([makeContainer("agent", [
    { name: "http_proxy", value: PROXY_URL }
  ])]);
  const result = handleValidateAdmission(review, PROXY_URL);
  assert.equal(result.response.allowed, true);
});

test("validate: returns 403 status code on denial", () => {
  const review = makeAdmissionReview([makeContainer("agent", [])]);
  const result = handleValidateAdmission(review, PROXY_URL);
  assert.equal(result.response.status.code, 403);
});

test("validate: handles missing request gracefully", () => {
  const result = handleValidateAdmission({}, PROXY_URL);
  assert.equal(result.response.allowed, false);
});

// ── Mutating webhook ─────────────────────────────────────────────────────────

test("mutate: injects all proxy env vars into container with no env", () => {
  const review = makeAdmissionReview([{ name: "agent" }]);  // no env field at all
  const result = handleMutateAdmission(review, PROXY_URL);
  assert.equal(result.response.allowed, true);
  assert.ok(result.response.patch, "patch should be set");
  const patches = JSON.parse(Buffer.from(result.response.patch, "base64").toString());
  const addPatch = patches.find(p => p.path === "/spec/containers/0/env");
  assert.ok(addPatch, "should add env array");
  assert.ok(addPatch.value.some(e => e.name === "HTTP_PROXY" && e.value === PROXY_URL));
  assert.ok(addPatch.value.some(e => e.name === "NO_PROXY"));
});

test("mutate: injects only missing proxy vars when container has partial env", () => {
  const review = makeAdmissionReview([makeContainer("agent", [
    { name: "MY_APP_VAR", value: "foo" }
  ])]);
  const result = handleMutateAdmission(review, PROXY_URL);
  const patches = JSON.parse(Buffer.from(result.response.patch, "base64").toString());
  const names = patches.map(p => p.value?.name);
  assert.ok(names.includes("HTTP_PROXY"));
  assert.ok(names.includes("HTTPS_PROXY"));
  assert.ok(!names.includes("MY_APP_VAR"), "should not re-add existing vars");
});

test("mutate: produces no patch when all proxy vars already present", () => {
  const review = makeAdmissionReview([makeContainer("agent", proxyEnvs())]);
  const result = handleMutateAdmission(review, PROXY_URL);
  assert.equal(result.response.allowed, true);
  assert.equal(result.response.patch, undefined, "no patch needed");
});

test("mutate: patches all containers independently", () => {
  const review = makeAdmissionReview([
    { name: "agent-a" },
    { name: "agent-b" }
  ]);
  const result = handleMutateAdmission(review, PROXY_URL);
  const patches = JSON.parse(Buffer.from(result.response.patch, "base64").toString());
  const paths = patches.map(p => p.path);
  assert.ok(paths.some(p => p.startsWith("/spec/containers/0/")));
  assert.ok(paths.some(p => p.startsWith("/spec/containers/1/")));
});

test("mutate: patchType is JSONPatch when patches are applied", () => {
  const review = makeAdmissionReview([{ name: "agent" }]);
  const result = handleMutateAdmission(review, PROXY_URL);
  assert.equal(result.response.patchType, "JSONPatch");
});

// ── Manifest generators ──────────────────────────────────────────────────────

test("NetworkPolicy blocks all egress except proxy and DNS", () => {
  const policy = generateNetworkPolicy({ namespace: "agents", scopezeroPort: 8788 });
  assert.equal(policy.kind, "NetworkPolicy");
  assert.equal(policy.metadata.namespace, "agents");
  assert.equal(policy.spec.policyTypes[0], "Egress");
  const ports = policy.spec.egress.flatMap(e => e.ports || []);
  assert.ok(ports.some(p => p.port === 8788));
  assert.ok(ports.some(p => p.port === 53));
});

test("NetworkPolicy pins DNS egress to the cluster resolver, not 0.0.0.0", () => {
  for (const policy of [
    generateNetworkPolicy({ namespace: "agents" }),
    generateDefaultDenyEgressPolicy({ namespace: "agents" })
  ]) {
    const dnsRule = policy.spec.egress.find(e => (e.ports || []).some(p => p.port === 53));
    assert.ok(dnsRule, "a DNS egress rule exists");
    assert.ok(dnsRule.to, "DNS egress must be scoped (not open to 0.0.0.0/0)");
    const target = dnsRule.to[0];
    assert.equal(target.namespaceSelector.matchLabels["kubernetes.io/metadata.name"], "kube-system");
    assert.equal(target.podSelector.matchLabels["k8s-app"], "kube-dns");
  }
});

test("MutatingWebhookConfig has failurePolicy Fail", () => {
  const cfg = generateMutatingWebhookConfig({ serviceHost: "scopezero.internal" });
  assert.equal(cfg.kind, "MutatingWebhookConfiguration");
  assert.equal(cfg.webhooks[0].failurePolicy, "Fail");
});

test("ValidatingWebhookConfig has failurePolicy Fail", () => {
  const cfg = generateValidatingWebhookConfig({ serviceHost: "scopezero.internal" });
  assert.equal(cfg.kind, "ValidatingWebhookConfiguration");
  assert.equal(cfg.webhooks[0].failurePolicy, "Fail");
});

test("MutatingWebhookConfig URL points to /v1/admission/mutate", () => {
  const cfg = generateMutatingWebhookConfig({ serviceHost: "10.0.0.1", servicePort: 8788 });
  assert.ok(cfg.webhooks[0].clientConfig.url.includes("/v1/admission/mutate"));
});

test("ValidatingWebhookConfig covers CREATE and UPDATE operations", () => {
  const cfg = generateValidatingWebhookConfig({ serviceHost: "scopezero.internal" });
  const ops = cfg.webhooks[0].rules[0].operations;
  assert.ok(ops.includes("CREATE"));
  assert.ok(ops.includes("UPDATE"));
});

test("default-deny egress policy selects all pods and only allows proxy + DNS", () => {
  const policy = generateDefaultDenyEgressPolicy({ namespace: "agents", scopezeroPort: 8788 });
  assert.equal(policy.kind, "NetworkPolicy");
  assert.equal(policy.metadata.name, "scopezero-default-deny-egress");
  assert.equal(policy.metadata.namespace, "agents");
  // Empty podSelector → applies to every pod, including unlabelled ones.
  assert.deepEqual(policy.spec.podSelector, {});
  assert.deepEqual(policy.spec.policyTypes, ["Egress"]);
  const ports = policy.spec.egress.flatMap(e => e.ports || []);
  assert.ok(ports.some(p => p.port === 8788));
  assert.ok(ports.some(p => p.port === 53));
});

test("generateFullEnforcementManifests includes the namespace default-deny", () => {
  const manifests = generateFullEnforcementManifests({ serviceHost: "scopezero.internal" });
  const kinds = manifests.map(m => m.kind);
  assert.ok(kinds.includes("NetworkPolicy"));
  assert.ok(kinds.includes("MutatingWebhookConfiguration"));
  assert.ok(kinds.includes("ValidatingWebhookConfiguration"));
  // Two NetworkPolicies now: namespace default-deny + labelled enforce.
  const names = manifests.filter(m => m.kind === "NetworkPolicy").map(m => m.metadata.name);
  assert.ok(names.includes("scopezero-default-deny-egress"));
  assert.ok(names.includes("scopezero-enforce-proxy-egress"));
  assert.equal(manifests.length, 4);
});
