# vhs recording script for the ScopeZero breach demo.
# Render with:  vhs gtm/demo.tape   (run from the project root)
# Produces a shareable GIF + MP4 of the demo running.

Output gtm/scopezero-demo.gif
Output gtm/scopezero-demo.mp4

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 920
Set Padding 24
Set Theme "Catppuccin Mocha"

Sleep 800ms
Type "# ScopeZero — a hijacked AI agent vs. a signed, time-boxed mission"
Sleep 1s
Enter
Sleep 1s
Type "npm run demo:breach"
Sleep 800ms
Enter
Sleep 7s
Sleep 4s
