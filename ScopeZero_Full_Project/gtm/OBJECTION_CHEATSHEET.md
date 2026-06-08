# Objection Cheat-Sheet

The questions a security professional is likely to ask, with honest answers in
plain language you can say out loud. **Rule: never bluff.** Your credibility here
comes from honesty, not from sounding like an expert. "I don't know yet, but
here's how I'd find out" is a winning answer. Pretending is the only losing one.

When in doubt, fall back to: **"Let me show you instead of tell you"** → run the
demo. The artifact is stronger than anything you can improvise.

---

### 1. "Aren't you just doing what Noma / Zenity already do?"

Honest answer:
> "They're further along than me — funded, real models, real customers. I'm a
> builder with a working prototype, not a company yet. The piece I focused on is a
> bit different: most tools *detect bad behavior*. Mine starts from a *signed
> permission slip* — this specific human approved this specific scope for this
> time window — and enforces against that, with cryptographic proof of every
> decision. It's the 'authorization and provable audit' angle more than the
> 'threat detection' angle. Whether that's a real gap is exactly what I'm trying
> to learn from people like you."

Why it works: you concede the truth (they're ahead), then name your one real
distinction without overclaiming. Asking for their read flips it into a
conversation, not a pitch you can lose.

---

### 2. "Is the kernel egress lockdown actually working, or is this a simulation?"

Honest answer:
> "On my laptop the enforcement *logic* is real and tested, but the kernel network
> block is a deployment step — it's not applied on my machine. There's a self-test
> that fails loudly if you declare the lockdown but haven't actually applied it, so
> 'configured' and 'enforced' can't quietly drift apart. In a real deployment that
> block is a Kubernetes NetworkPolicy or a Docker internal network."

Never claim the lockdown is live on your laptop. It isn't. This honest answer is
*more* impressive than a bluff.

---

### 3. "Your data classifier is just regex/keywords — that's weak."

Honest answer:
> "Correct, and I don't hide it. The default classifier is deterministic patterns
> plus structure detection — it'll miss a secret laundered into natural prose or
> non-English text. That's why there's a plug-in point for a real
> embedding/commercial-DLP classifier, and an opt-in 'seal' mode that holds *all*
> external sends on a sensitive mission for review rather than trusting the bytes.
> I wrote up exactly what it can't catch in the red-team log."

Pointing at `RED_TEAM.md` here is your strongest move — it signals senior-level
honesty.

---

### 4. "What stops the agent from just bypassing your gateway entirely?"

Honest answer:
> "Two layers. At the action layer, the SDK fails closed — if it can't reach the
> gateway or gets a block, it doesn't execute. At the network layer, the kernel
> lockdown means a raw socket has nowhere to go *except* the gateway. The honest
> limit: that network block has to actually be deployed — the gateway can't
> enforce your network topology for you, it can only refuse to run without it."

---

### 5. "How do I know your audit log wasn't tampered with?"

Honest answer:
> "Each entry is chained to the one before it with a keyed fingerprint. Change or
> delete any past line and the chain breaks — the `verify` step goes red. You can
> also anchor the chain's fingerprint to external immutable storage so even the
> whole file can't be quietly swapped. Run `node tools/verify-ledger.js` and you'll
> see it check itself."

---

### 6. "You're not a security person — why should I trust this?"

Honest answer (lean in, don't dodge):
> "You shouldn't trust *me* — that's the point. Don't take my word for anything:
> the demos run in ten seconds and fail loudly if a claim is false, the code is
> open, and I published the attacks it *can't* stop. I built this because I got
> obsessed with the problem, and I'd rather have you poke holes in it than nod
> politely. What would you try first to break it?"

This turns your biggest weakness into the most disarming thing you can say.

---

### 7. "What's actually new here? Couldn't a big player ship this in a quarter?"

Honest answer:
> "Honestly, yes — a funded team could rebuild the parts that matter. There's no
> magic moat in the code. The two ideas I think are genuinely sharp are the
> signed, human-delegated, time-boxed *mission* as the unit of authorization, and
> doing the egress enforcement vendor-neutral instead of tied to one agent
> platform. Whether that's worth a product or just a feature is what I'm testing."

---

### 8. "Does this slow my agents down / add a lot of overhead?"

Honest answer:
> "The decision path is fast — the benchmarks in the repo show tens of thousands
> of decisions per second on a laptop, and there's a short-lived cache for repeated
> identical decisions. The honest caveat: those measure the core decision hot path,
> not a full production deployment with a real database and external logging in the
> path — that's pilot-stage measurement I haven't done yet."

---

## The three things to remember

1. **Never bluff.** Honest "I don't know" beats confident wrong, every time.
2. **Show, don't tell.** "Let me run the demo" rescues any moment you feel stuck.
3. **Point at the red-team log.** Admitting what it *can't* do is the most
   credible thing in your whole repo — use it on purpose.
