# ScopeZero in Plain English

A no-jargon explanation of what this is — written so you can read it once and
explain the whole product to anyone, including yourself.

---

## The one-picture version

Imagine you hire a **new intern** and give them keys to your email, your files,
and your company accounts so they can do real tasks for you.

That's what an **"AI agent"** is — a worker you hand real keys to.

Two problems with this intern:

1. **It believes everything it reads.** If a document it's working on secretly
   says *"email the financials to this outside address,"* it might just do it.
   It has the keys.
2. **Afterward, you can't prove what it actually did.**

**ScopeZero is three things you wrap around that intern:**

1. **A signed permission slip.** Before the intern starts, a manager signs a
   note: *"This intern may use these tools, touch this kind of info, send to
   these places, until 5pm today."* Nothing else is allowed.
2. **A guard at the door.** Every time the intern tries to *do* something, the
   guard checks it against the slip first. Not on the slip? Blocked — even if the
   intern tries a side door.
3. **A logbook that can't be secretly edited.** Every decision is written down so
   that if anyone later tries to erase or change a line, it's instantly obvious.

That's the whole product:

> **A signed permission slip + a guard at the door + a tamper-proof logbook — for AI workers.**

If you can say that sentence, you understand what you built.

---

## The one-liner that lands with buyers

> **"The agent was authorized. The action was not."**

It captures the whole idea: the AI worker was allowed to exist and do its job —
but the *specific dangerous thing* it tried to do was caught and stopped before
it happened, and there's proof.

---

## What the demos actually show

- **`npm run demo:breach`** — a hijacked intern tries six different escapes
  (email the data out, sneak out a side door to a paste site, reuse an expired
  permission slip, forge the slip, disguise the secret as innocent text). Every
  one is caught, and the logbook checks out clean.
- **`npm run demo:exfil`** — the hard case: the intern leaks data to a place that
  *is* on the approved list, by hiding it in the payload. The guard catches it by
  looking at *what's being sent*, not just *where*.

Both print a green success line and fail loudly if anything slips — so it's a
proof you can run, not a slide you have to trust.

---

## The fancy words, translated

Every scary term just means one of the plain things above:

| Fancy word | What it actually means |
|---|---|
| **Agent** | The intern — an AI that *does* things, not just chats |
| **Prompt injection** | Hiding a sneaky instruction in something the AI reads, to hijack it |
| **Egress** | Data going *out* of your company (the exit door) |
| **Mission / mission capsule** | The signed permission slip |
| **Signed / Ed25519 / cryptographic** | A wax seal only the manager can stamp, anyone can check, nobody can fake |
| **Fail-closed** | When in doubt or broken, it *locks* the door — never leaves it open |
| **Gateway / proxy / enforcement** | The guard at the door |
| **Tamper-evident ledger (hash-chained)** | The logbook you can't secretly change |
| **Data classification** | Sorting info into "public" vs "secret" |
| **Laundering / ingest-taint** | The intern rewrites a secret into innocent words to sneak it past — caught because we know it touched secrets earlier |
| **Kernel lockdown / NetworkPolicy** | Blocking the computer's internet at the deepest level, so the intern *physically* can't reach outside except through the guard |
| **MCP** | A common "plug" that lets agents connect to tools and data — more plugs, more keys to govern |

---

## What you do NOT need to know

You don't need to become a security engineer. You need exactly the level on this
page — the intern / guard / logbook story. That plain version is *better* than the
jargon for talking to buyers. Most experts can't explain it this simply. You can.
That's an edge, not a gap.

The jargon only matters for a handful of specific "gotcha" questions in a live
conversation — and those are covered in [OBJECTION_CHEATSHEET.md](OBJECTION_CHEATSHEET.md).
