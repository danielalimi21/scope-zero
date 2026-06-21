# Founder call prep — ScopeZero

Everything you need to walk into a 20-minute call and convert it. Read it twice.
Golden rule: **listen more than you talk, be honest about what's built vs not,
and always leave with a concrete next step.**

---

## 1. How it works — so you can explain it (not bluff it)

One-liner: *ScopeZero binds every AI-agent action to a signed, human-approved
authority it can't exceed — and proves it.*

Four layers. Be able to say each in plain English:

**1. Authority Grant (the signed permission slip).**
A human approves a narrow scope for the agent — which tools, which data, which
destinations, for how long. ScopeZero signs that into a token using Ed25519
(public-key cryptography). The agent carries the token but only ScopeZero holds
the private key, so the agent **can't forge it or widen it**. It's also
time-boxed — it expires.
→ Say: "The agent gets a signed, expiring permission slip it can't tamper with."

**2. The Gate (the check before every action).**
Before any action runs, ScopeZero turns it into a structured descriptor — tool,
operation, data class, destination, whether money or privilege is involved — and
checks it against the signed grant plus policy. Three outcomes: in-scope runs
autonomously; out-of-scope is blocked before execution; irreversible actions
(payments, privilege changes, external sends) are held for a human co-sign.
→ Say: "Every action is checked against the slip before it runs — allow, block,
or hold for a human."

**3. Containment (the part that holds against a hijacked agent).**
This is the hard, differentiated part. Even if a prompt-injected agent ignores
the SDK and opens its own network connection, its egress is forced through
ScopeZero at the kernel/cluster layer (a Kubernetes NetworkPolicy, or a Docker
internal network). It has **no other route out** — so it physically can't reach a
destination outside its grant.
→ Say: "A compromised agent can't route around it — containment is at the network
layer, not just an SDK it could skip." (Honest caveat below.)

**4. Proof (the tamper-evident receipt).**
Every decision — allow, block, co-sign — is written to a hash-chained ledger:
each entry includes the hash of the one before it, keyed with a secret (HMAC).
Change any entry and the chain breaks, so verification fails. Anyone can verify
it independently.
→ Say: "Every decision lands on a tamper-evident record your customer can verify
themselves."

The thesis (memorize this): **contain the action, don't detect the attack.**
Detection gives you a probability after the fact; containment gives you a
guarantee before. That's what matters when the action can't be undone.

---

## 2. The hard questions — and your honest answers

**"How is this different from a guardrail / prompt firewall (Operant, Prompt
Security, Lasso)?"**
They inspect and detect — content, prompts, intent. An injected agent can open
its own socket and route around an SDK, and "probably safe" doesn't hold for an
irreversible action. I enforce and contain at the layer it can't bypass, and I
prove it. Complementary to them, not competitive.

**"How is this different from agent identity / IAM (Astrix, Aembit, Token, Oasis)?"**
They handle *who* the agent is and *what it can access* — identity and access.
I handle *what it does with that access* at the action level: the enforcement,
the co-sign on irreversible actions, and the proof. I sit on top of them.

**"It's just you?"**
Yes — I designed, built, and red-teamed it end to end. That means I understand
every line and move fast. (Don't apologize for it. Don't claim a team or funding
you don't have.)

**"Is it production-ready?"**
It's built and working — running gateway, SDK, 280 automated tests, adversarially
red-teamed, load-tested at ~1,300 authorizations/sec with the audit trail
verifying clean under concurrency. Honest boundary: it hasn't had an external
security audit yet — that's the next bar, and I'd want to do it alongside a
first design partner. Single-replica is fully correct; the ledger is now
multi-replica-safe via a shared sequencer.

**"Latency / overhead?"**
The per-action check is in-process and fast — ~50ms median, ~1,300/sec on a
laptop. The only deliberate "slowdown" is the human co-sign on irreversible
actions — which is the point, not a bug.

**"Why would I embed a dependency on a solo founder in my critical path?"**
You wouldn't, blindly — and I'm not asking you to. That's exactly why I'm looking
for a design partner to harden it together on a real workload, why it's open to
your inspection and an external audit, and why you'd start on a non-critical path
and prove it before trusting it. (This honesty wins more than a confident dodge.)

**"What's your traction?"**
Pre-revenue and early — I'm talking to the teams closest to this to find where
it's most useful. The product is real and proven; market validation is exactly
what I'm doing now. (Never invent customers.)

**"How does the kernel containment actually work?"**
On Kubernetes, a NetworkPolicy plus an admission webhook forces all agent egress
through the ScopeZero proxy and rejects pods that strip it; off-Kubernetes, a
Docker internal network does the same. The agent has no internet route except the
proxy, which only allows destinations in the signed mission. Honest caveat: that
hard guarantee needs the lockdown actually applied — bare SDK with no network
lockdown is governance and audit only, and I say so.

**"What's the threat model?"**
A prompt-injected agent that still calls through honestly (it controls the tool,
payload, and context) plus a network attacker opening raw sockets. Missions are
Ed25519-signed, so they can't be forged. The content classifier is advisory — the
deterministic gates, the kernel containment, and the human co-sign are the real
controls.

**"What do you actually want from this call?"**
Right now: a design partner to harden it on a real workload and learn where it's
most valuable. I'm not asking for money — I'm asking to solve a real problem with
you.

---

## 3. The 20-minute call structure

**Minutes 0–2 — lower the stakes.** "Thanks for the time. I mostly want to hear
how you think about this, and show you what I built if it's useful — and tell me
where I'm wrong." (You're not pitching; you're learning.)

**Minutes 2–9 — discovery (ask, then shut up).** Five questions:
1. What's the most irreversible thing your agent can do today?
2. Has a customer or your security team ever slowed a launch over what the agent
   *could* do?
3. How do you handle that now — guardrails, human approval, or "we don't let it
   do that yet"?
4. Where do you want more autonomy but can't get comfortable?
5. If the agent provably couldn't exceed what a human authorized, what would that
   unlock?

**Minutes 9–16 — show.** Run the demo (script below) and the diagram. Tie it
directly to what they just told you. ("You said X — here's exactly that.")

**Minutes 16–20 — close on a next step.** Propose one concrete thing:
- "Want to try it against your actual workload as a design partner?" or
- "Can I do a technical deep-dive with your eng team?" or
- "Who else should see this?"
Leave with a scheduled next step, never a vague "let's stay in touch."

---

## 4. The 60-second demo script (`npm run demo`)

Say this while it runs:
- "One agent, given a signed authority to do cloud-ops work."
- "It does its in-scope job — runs autonomously." *(step 2)*
- "Now it's hijacked and tries to grant itself admin — blocked before it reaches
  AWS." *(step 3)*
- "Tries to wire money out — blocked." *(step 4)*
- "Here's the key part: a legitimate, in-scope change — but it's irreversible, so
  it's held for a human co-sign, approved, then runs." *(step 5)*
- "And every decision is on a tamper-evident receipt that verifies clean — that's
  what your customer can check." *(step 6)*
- "Exit code zero — that's an executable proof, not a slide."

Practice this out loud 3 times. Confirm `npm run demo` runs from a clean clone
*before* the call — a broken demo ends it.

---

## 4b. The deployment story (use this when they ask "how risky is adoption?")

ScopeZero has two modes. Lead with this — it removes their biggest objection:

- **Monitor mode (day one, whole fleet):** ScopeZero records every agent action
  and the decision it *would* make — block, co-sign, allow — into the
  tamper-evident ledger, but it **never blocks**. Zero production risk. They get
  full visibility across their entire agent fleet immediately, and a provable
  record most teams don't have today. (Capacity is there: ~1,300 authorizations/
  sec across hundreds of agents in testing.)
- **Enforce mode (when they trust it):** flip on blocking + human co-sign for the
  irreversible actions, starting where it matters most.

Say: *"Deploy it across your whole fleet on day one in observe mode — it can't
break anything, it just shows you what every agent does and what it would have
caught. Flip enforcement on when you're ready. Start broad and safe, not narrow."*
That's strong **and** low-risk — exactly what a buyer wants to hear.

## 5. Golden rules

- Listen more than you talk. The discovery questions matter more than the demo.
- Honesty is your edge. "Not audited yet," "it's just me," "here's where it
  breaks" — technical people trust that. A confident dodge loses them.
- Don't oversell. The demo and your candor do the work.
- Always leave with a specific, scheduled next step.
- Have a Calendly link ready so a "yes" gets booked instantly.
