# Demo video script (90 seconds)

Record a terminal (asciinema or Loom). One take, no slides. The product proves
itself — your job is narration. Target length 90s; a 30s cut is at the bottom.

## Setup (before recording)

```bash
cd scope-zero/ScopeZero_Full_Project && npm install
clear   # clean terminal, large font
```

## The take

**[0:00–0:10] The stakes.** Say while the terminal sits empty:

> "Your AI agents have real credentials. One prompt injection turns 'summarize
> these docs' into 'email the customer data out.' Here's what stops it."

**[0:10–0:20] Run it.** Type:

```bash
npm run demo:breach
```

> "A diligence agent gets a signed mission: read-only, one data room, expires in
> 30 minutes. Then it gets prompt-injected. Watch."

**[0:20–1:05] Narrate each CONTAINED line as it prints** (the demo pauses are
already paced):

- > "It tries to **email the data out** through the SDK — blocked, out of mission."
- > "It skips the SDK and opens a **raw tunnel to pastebin** — blocked at the network."
- > "It waits and **replays the mission after it expired** — blocked, stale."
- > "It **forges the signed capsule** to widen its scope — signature fails, blocked."

**[1:05–1:20] The proof.** Point at the last line:

> "And every attempt is sealed in a hash-chained ledger that just verified
> clean. That's the part your auditor wants: provable, tamper-evident, 'here's
> exactly what the agent did.'"

**[1:20–1:30] The ask.** Plain:

> "Vendor-neutral — GitHub, Slack, Gmail, AWS, any MCP server. If you're running
> agents with real credentials, I'll deploy this against one of yours for free
> and we'll watch it contain a real injection together. Link below."

End on the green `All escape attempts contained. This is the guarantee.` line.

## 30-second cut (for LinkedIn / cold DM)

1. **[0:00–0:08]** "Agents have real credentials. One prompt injection and they
   exfiltrate. Here's the gate that stops it." → run `npm run demo:breach`.
2. **[0:08–0:24]** Let the CONTAINED lines scroll; say "SDK exfil — blocked.
   Raw tunnel — blocked. Expired mission — blocked. Forged capsule — blocked."
3. **[0:24–0:30]** "All contained, ledger verified. Running agents? Let's talk."

## Tips

- Big font, dark theme, no other tabs. The green ✓ CONTAINED lines are the hook
  — don't talk over the moment they appear, let them land.
- Don't explain the architecture. The demo *is* the argument. Save mechanism for
  the call.
- Post the 30s cut; link the 90s + `gtm/QUICKSTART.md` for anyone who leans in.
