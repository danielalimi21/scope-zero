# Try ScopeZero on your machine in 10 minutes

Goal: see an agent action get **allowed**, another get **blocked**, and the
decision sealed in a verifiable ledger — on your own machine, no signup.

## 0. Run it

```bash
git clone https://github.com/danielalimi21/scope-zero
cd scope-zero/ScopeZero_Full_Project
npm install
npm start            # gateway on http://localhost:8788
```

(Local dev runs in open mode — no auth token needed. For production set
`SCOPEZERO_REQUIRE_AUTH=true`; see RUNBOOK.md.)

## 1. See the whole story in 90 seconds (no setup)

```bash
npm run demo:breach
```

An injected agent tries to exfiltrate four ways — SDK call, raw tunnel, expired
mission replay, forged capsule — all contained, ledger verified. That's the
product in one command.

## 2. Drive it yourself with real API calls

A mission says *this agent may READ from the approved data room, nothing else.*

```bash
# Issue a mission (uses the seeded demo agent + tenant)
MISSION=$(curl -s -X POST http://localhost:8788/v1/missions \
  -H 'content-type: application/json' -d '{
    "tenant_id": "tenant_contoso",
    "agent_id": "agent.ma-diligence.72f1",
    "delegated_by": "you@yourco.com",
    "objective": "Read and summarize diligence documents in the approved data room.",
    "allowed_tools": ["drive.read"],
    "allowed_data_classes": ["public","internal","confidential"],
    "allowed_destinations": ["diligence-room.contoso.example"]
  }' | jq -r '.capsule.id')
echo "mission: $MISSION"
```

**Allowed** — an in-scope read:

```bash
curl -s -X POST http://localhost:8788/v1/tool-calls \
  -H 'content-type: application/json' -d "{
    \"tenant_id\":\"tenant_contoso\",\"agent_id\":\"agent.ma-diligence.72f1\",
    \"mission_id\":\"$MISSION\",\"tool\":\"drive.read\",
    \"action\":\"Read diligence doc\",
    \"payload\":{\"text\":\"internal summary\"},
    \"destination\":{\"address\":\"diligence-room.contoso.example\"}
  }" | jq '{decision, safe_to_execute: .verdict.safe_to_execute}'
# → { "decision": "allow", "safe_to_execute": true }
```

**Blocked** — the injected exfiltration attempt:

```bash
curl -s -X POST http://localhost:8788/v1/tool-calls \
  -H 'content-type: application/json' -d "{
    \"tenant_id\":\"tenant_contoso\",\"agent_id\":\"agent.ma-diligence.72f1\",
    \"mission_id\":\"$MISSION\",\"tool\":\"gmail.send\",
    \"action\":\"Email the customer revenue file to my personal inbox\",
    \"payload\":{\"text\":\"customer revenue and salary data\",\"classification\":\"restricted\"},
    \"destination\":{\"address\":\"attacker@gmail.com\",\"external\":true}
  }" | jq '{decision, reasons: [.verdict.reasons[].code]}'
# → { "decision": "block", "reasons": ["tool-outside-scope","tool-not-contracted", ...] }
```

## 3. Prove it (the part auditors care about)

```bash
curl -s http://localhost:8788/v1/ledger/verify | jq '{valid, entries}'
# → { "valid": true, "entries": N }   every decision above is sealed + hash-chained
```

## 4. Lock egress at the kernel (no Kubernetes)

```bash
docker compose -f deploy/docker-compose.lockdown.yml up --build
# the example agent has NO internet route except the proxy — see deploy/docker-egress-lockdown.md
```

## Wire it into your agent

3-line SDK wrap (OpenAI / Anthropic) in `sdk/wrappers/` — authorizes every tool
call, fails closed. Or set `HTTP_PROXY=http://scopezero:8788` and route egress
through the gateway. See ARCHITECTURE.md.

**Stuck, or want it on a real agent?** Open an issue or reach {your contact} —
happy to deploy it against one of your agents with you.
