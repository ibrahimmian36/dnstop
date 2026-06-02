# vhs tape for the dnstop demo GIF.
# Record on a Linux box with yeet installed:
#   vhs assets/dnstop.tape
#
# Produces assets/dnstop.gif. In one pane run dnstop, in another run
# tests/simulate_dns_threats.sh to trigger the DGA + tunnel alerts.

Output assets/dnstop.gif
Set FontSize 13
Set Width 1400
Set Height 800
Set Theme "Dracula"

Type "yeet run main.js"
Enter
Sleep 3s
# (in a separate shell: ./tests/simulate_dns_threats.sh)
Sleep 25s
Ctrl+C
