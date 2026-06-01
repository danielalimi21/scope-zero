# Fail-closed egress without Kubernetes

ScopeZero's hard guarantee — "an agent that skips the SDK is still contained" —
needs the agent's egress blocked at the kernel so it physically cannot reach the
internet except through the ScopeZero proxy. On Kubernetes that's a
NetworkPolicy. **You do not need Kubernetes to get it.** Docker's own network
isolation gives the same kernel-enforced block.

## Enforcement tiers (be honest about which you're on)

| Tier | Mechanism | Guarantee |
|------|-----------|-----------|
| **Strongest** | K8s NetworkPolicy (`GET /v1/deployment/k8s-manifests`) | Kernel drops all egress except the proxy + cluster DNS. Bypass-proof. |
| **Strong (no K8s)** | Docker **internal network** (below) | Agent container has no route to the internet; its only reachable hop is the proxy. Kernel-enforced by Docker. |
| **Governance only** | SDK wrapper alone (`HTTP_PROXY` + `Proxy-Authorization`) | Authorizes + audits, but a raw socket can ignore the proxy. Use only when you control the agent code and accept that. |

Pick a tier deliberately. Tiers 1–2 are real containment; tier 3 is honor-system.

## Docker internal-network lockdown (recommended, no K8s)

Put the agent on an `internal: true` Docker network — Docker gives it **no
gateway to the host/internet**. Attach the ScopeZero proxy to both that internal
network *and* a normal bridge with internet. The agent's only path out is
through ScopeZero; a raw socket to `api.github.com` simply has nowhere to route.

```yaml
# deploy/docker-compose.lockdown.yml  (run: docker compose -f deploy/docker-compose.lockdown.yml up)
networks:
  agents-internal:
    internal: true     # no egress to the internet — the kernel enforces this
  egress:
    driver: bridge     # has internet; only ScopeZero is attached here

services:
  scopezero:
    image: scopezero/runtime:0.1.0
    networks: [agents-internal, egress]   # bridges the two
    environment:
      SCOPEZERO_REQUIRE_AUTH: "true"
      SCOPEZERO_SIGNING_SECRET: "replace-me"
      SCOPEZERO_AUTH_SECRET: "replace-me"

  agent:
    image: your-agent:latest
    networks: [agents-internal]           # internet-isolated
    environment:
      HTTP_PROXY:  "http://scopezero:8788"
      HTTPS_PROXY: "http://scopezero:8788"
      http_proxy:  "http://scopezero:8788"
      https_proxy: "http://scopezero:8788"
      NO_PROXY:    "localhost,127.0.0.1,scopezero"
```

Test it holds: from inside the agent container, a direct call must fail, a
proxied call (with a valid mission token) must work:

```bash
docker compose -f deploy/docker-compose.lockdown.yml exec agent \
  sh -c 'curl -m5 https://example.com'                 # hangs/fails — no route out
docker compose -f deploy/docker-compose.lockdown.yml exec agent \
  sh -c 'curl -m5 -x http://scopezero:8788 https://example.com'   # gated by ScopeZero
```

If the first command reaches the internet, the lockdown is misconfigured — the
agent is on a network with a gateway. It must be on the `internal: true` net only.

## Bare `docker run` (iptables alternative)

No compose? Drop egress with firewall rules, allowing only the proxy host. Run
this as the container's entrypoint prefix (needs `--cap-add=NET_ADMIN`):

```sh
#!/bin/sh
# Allow loopback + DNS + the ScopeZero proxy; drop everything else outbound.
SCOPEZERO_IP="${SCOPEZERO_IP:?set to the proxy container/host IP}"
iptables -P OUTPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -d "$SCOPEZERO_IP" -p tcp --dport 8788 -j ACCEPT
exec "$@"
```

The internal-network approach is preferred — it needs no extra capability and
can't be turned off from inside the container. Use iptables only when you can't
shape the Docker network.

## What this does and doesn't give you

- **Does:** kernel-enforced fail-closed egress without Kubernetes — the agent
  cannot exfiltrate by skipping the SDK.
- **Doesn't:** inspect what flows *through* an allowed HTTPS tunnel (TLS is
  opaque — that's the SDK/action layer's job), or stop a compromised *host*
  (only a separate trust boundary does). Same honest boundary as the K8s tier.
