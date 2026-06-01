// Kubernetes admission webhook handlers.
//
// Deploy strategy (fail-closed, three layers):
//   1. NetworkPolicy       — blocks direct egress at kernel level, no bypass possible
//   2. MutatingWebhook     — auto-injects HTTP_PROXY env vars into every new pod
//   3. ValidatingWebhook   — rejects pods that explicitly removed the proxy config
//
// Both webhooks use failurePolicy: Fail so ScopeZero going down prevents
// new agent pods from starting rather than silently letting them through.

const PROXY_ENV_NAMES = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"];
const NO_PROXY_VALUE = "localhost,127.0.0.1";

// DNS egress pinned to the in-cluster resolver (kube-dns) rather than allowed to
// any address. Allowing UDP/TCP 53 to 0.0.0.0/0 is an open exfiltration channel:
// an injected agent can tunnel data out as DNS queries to its own nameserver.
// Restricting to kube-dns kills the direct-to-arbitrary-resolver path.
function dnsEgressRule() {
  return {
    to: [
      {
        namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "kube-system" } },
        podSelector: { matchLabels: { "k8s-app": "kube-dns" } }
      }
    ],
    ports: [
      { protocol: "UDP", port: 53 },
      { protocol: "TCP", port: 53 }
    ]
  };
}

// ── Validating webhook ──────────────────────────────────────────────────────

export function handleValidateAdmission(admissionReview, expectedProxyUrl) {
  const request = admissionReview?.request;
  if (!request) return denyReview("", "Invalid AdmissionReview — missing request field.");

  const allContainers = [
    ...(request.object?.spec?.containers || []),
    ...(request.object?.spec?.initContainers || [])
  ];

  const violations = allContainers
    .filter(c => !containerHasProxy(c, expectedProxyUrl))
    .map(c => c.name);

  if (violations.length > 0) {
    return denyReview(
      request.uid,
      `ScopeZero proxy enforcement: containers [${violations.join(", ")}] are missing ` +
      `HTTP_PROXY=${expectedProxyUrl}. ` +
      `All agent containers must route outbound traffic through ScopeZero. ` +
      `See GET /v1/deployment/lockdown for setup instructions.`
    );
  }

  return allowReview(request.uid);
}

// ── Mutating webhook ────────────────────────────────────────────────────────

export function handleMutateAdmission(admissionReview, proxyUrl) {
  const request = admissionReview?.request;
  if (!request) return denyReview("", "Invalid AdmissionReview — missing request field.");

  const containers = request.object?.spec?.containers || [];
  const patches = [];

  containers.forEach((container, idx) => {
    const existing = new Set((container.env || []).map(e => e.name));
    const toInject = buildProxyEnvVars(proxyUrl).filter(e => !existing.has(e.name));
    if (!toInject.length) return;

    if (!container.env || container.env.length === 0) {
      patches.push({ op: "add", path: `/spec/containers/${idx}/env`, value: toInject });
    } else {
      for (const envVar of toInject) {
        patches.push({ op: "add", path: `/spec/containers/${idx}/env/-`, value: envVar });
      }
    }
  });

  const response = { uid: request.uid, allowed: true };
  if (patches.length > 0) {
    response.patchType = "JSONPatch";
    response.patch = Buffer.from(JSON.stringify(patches)).toString("base64");
  }

  return { apiVersion: "admission.k8s.io/v1", kind: "AdmissionReview", response };
}

// ── Manifest generators ─────────────────────────────────────────────────────

export function generateNetworkPolicy({ namespace = "default", scopezeroPort = 8788, scopezeroServiceName = "scopezero" } = {}) {
  return {
    apiVersion: "networking.k8s.io/v1",
    kind: "NetworkPolicy",
    metadata: {
      name: "scopezero-enforce-proxy-egress",
      namespace,
      annotations: {
        "scopezero.io/purpose": "Block all direct outbound connections. Egress must go through ScopeZero proxy."
      }
    },
    spec: {
      // Apply to pods labelled scopezero.io/enforce=true
      podSelector: { matchLabels: { "scopezero.io/enforce": "true" } },
      policyTypes: ["Egress"],
      egress: [
        {
          // Only allow TCP to the ScopeZero proxy
          to: [{ podSelector: { matchLabels: { app: scopezeroServiceName } } }],
          ports: [{ protocol: "TCP", port: scopezeroPort }]
        },
        // DNS to the cluster resolver only — not to arbitrary nameservers.
        dnsEgressRule()
      ]
    }
  };
}

// Namespace-wide default-deny egress. The labelled policy above only constrains
// pods opting in with scopezero.io/enforce=true; an unlabelled pod would have no
// egress policy selecting it and could reach anything. This policy selects EVERY
// pod in the namespace (empty podSelector) and permits egress only to the
// ScopeZero proxy and DNS, so a pod that forgot the enforce label is still boxed
// in by default rather than open.
export function generateDefaultDenyEgressPolicy({ namespace = "default", scopezeroPort = 8788, scopezeroServiceName = "scopezero" } = {}) {
  return {
    apiVersion: "networking.k8s.io/v1",
    kind: "NetworkPolicy",
    metadata: {
      name: "scopezero-default-deny-egress",
      namespace,
      annotations: {
        "scopezero.io/purpose": "Default-deny egress for ALL pods in the namespace. Only the ScopeZero proxy and DNS are reachable, including for pods missing the scopezero.io/enforce label."
      }
    },
    spec: {
      // Empty podSelector → selects every pod in the namespace.
      podSelector: {},
      policyTypes: ["Egress"],
      egress: [
        {
          to: [{ podSelector: { matchLabels: { app: scopezeroServiceName } } }],
          ports: [{ protocol: "TCP", port: scopezeroPort }]
        },
        // DNS to the cluster resolver only — not to arbitrary nameservers.
        dnsEgressRule()
      ]
    }
  };
}

export function generateMutatingWebhookConfig({ serviceHost, servicePort = 8788, namespace = "default", caBundle = "" } = {}) {
  return {
    apiVersion: "admissionregistration.k8s.io/v1",
    kind: "MutatingWebhookConfiguration",
    metadata: { name: "scopezero-proxy-injector" },
    webhooks: [{
      name: "proxy-inject.scopezero.io",
      clientConfig: {
        url: `https://${serviceHost}:${servicePort}/v1/admission/mutate`,
        caBundle: caBundle || "<base64-encoded-CA-cert>"
      },
      rules: [{
        apiGroups: [""],
        apiVersions: ["v1"],
        operations: ["CREATE"],
        resources: ["pods"],
        scope: "Namespaced"
      }],
      // Only inject into namespaces that opt in
      namespaceSelector: { matchLabels: { "scopezero.io/inject-proxy": "enabled" } },
      admissionReviewVersions: ["v1"],
      sideEffects: "None",
      failurePolicy: "Fail"   // ScopeZero down → no new pods. Fail-closed.
    }]
  };
}

export function generateValidatingWebhookConfig({ serviceHost, servicePort = 8788, caBundle = "" } = {}) {
  return {
    apiVersion: "admissionregistration.k8s.io/v1",
    kind: "ValidatingWebhookConfiguration",
    metadata: { name: "scopezero-proxy-enforcer" },
    webhooks: [{
      name: "proxy-enforce.scopezero.io",
      clientConfig: {
        url: `https://${serviceHost}:${servicePort}/v1/admission/validate`,
        caBundle: caBundle || "<base64-encoded-CA-cert>"
      },
      rules: [{
        apiGroups: [""],
        apiVersions: ["v1"],
        operations: ["CREATE", "UPDATE"],
        resources: ["pods"],
        scope: "Namespaced"
      }],
      namespaceSelector: { matchLabels: { "scopezero.io/enforce": "true" } },
      admissionReviewVersions: ["v1"],
      sideEffects: "None",
      failurePolicy: "Fail"
    }]
  };
}

// Returns all three manifests as an ordered array ready for `kubectl apply -f`
export function generateFullEnforcementManifests({ serviceHost, servicePort = 8788, namespace = "default", caBundle = "" } = {}) {
  return [
    generateDefaultDenyEgressPolicy({ namespace, scopezeroPort: servicePort }),
    generateNetworkPolicy({ namespace, scopezeroPort: servicePort }),
    generateMutatingWebhookConfig({ serviceHost, servicePort, namespace, caBundle }),
    generateValidatingWebhookConfig({ serviceHost, servicePort, caBundle })
  ];
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function buildProxyEnvVars(proxyUrl) {
  return [
    ...PROXY_ENV_NAMES.map(name => ({ name, value: proxyUrl })),
    { name: "NO_PROXY", value: NO_PROXY_VALUE }
  ];
}

function containerHasProxy(container, expectedUrl) {
  const env = container.env || [];
  const httpProxy = env.find(e => e.name === "HTTP_PROXY" || e.name === "http_proxy");
  if (!httpProxy) return false;
  if (expectedUrl && httpProxy.value !== expectedUrl) return false;
  return true;
}

function allowReview(uid) {
  return { apiVersion: "admission.k8s.io/v1", kind: "AdmissionReview", response: { uid, allowed: true } };
}

function denyReview(uid, message) {
  return {
    apiVersion: "admission.k8s.io/v1",
    kind: "AdmissionReview",
    response: { uid, allowed: false, status: { code: 403, message } }
  };
}
