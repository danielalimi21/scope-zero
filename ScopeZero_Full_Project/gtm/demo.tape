# vhs recording script for the ScopeZero Authorized Autonomy demo.
# Render with:  vhs gtm/demo.tape   (run from the project root)
# Produces a shareable GIF + MP4 of the demo running.

Output gtm/scopezero-demo.gif
Output gtm/scopezero-demo.mp4

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 1000
Set Padding 24
Set Theme "Catppuccin Mocha"

Sleep 800ms
Type "# ScopeZero — Authorized Autonomy: an agent can act, but only what a human signed for"
Sleep 1s
Enter
Sleep 1s
Type "npm run demo"
Sleep 800ms
Enter
Sleep 8s
Sleep 4s
