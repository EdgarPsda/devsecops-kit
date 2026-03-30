# ─────────────────────────────────────────────────────────────
#  devsecops-kit — demo GIF
#  Run with: vhs devsecops-demo.tape
#
#  BEFORE RUNNING:
#    bash _dsk_mock.sh   ← writes the mock aliases into /tmp
#    vhs devsecops-demo.tape
# ─────────────────────────────────────────────────────────────

Output devsecops-demo.gif

Set Shell      "bash"
Set FontSize   14
Set Width      1100
Set Height     700
Set Theme      "Dracula"
Set Padding    24
Set TypingSpeed 55ms

# Load mock aliases silently
Hide
Type "source /tmp/_dsk_mock.sh 2>/dev/null"
Enter
Sleep 300ms
Show

# ══════════════════════════════════════════════════════════════
#  SCENE 1 — detect
# ══════════════════════════════════════════════════════════════
Type "devsecops detect"
Sleep 400ms
Enter
Sleep 2500ms

# ══════════════════════════════════════════════════════════════
#  SCENE 2 — init
# ══════════════════════════════════════════════════════════════
Type "devsecops init"
Sleep 400ms
Enter
Sleep 3500ms

# ══════════════════════════════════════════════════════════════
#  SCENE 3 — scan (all scanners)
# ══════════════════════════════════════════════════════════════
Type "devsecops scan"
Sleep 400ms
Enter
Sleep 5000ms

# ══════════════════════════════════════════════════════════════
#  SCENE 4 — sbom
# ══════════════════════════════════════════════════════════════
Type "devsecops sbom"
Sleep 400ms
Enter
Sleep 2500ms

# ══════════════════════════════════════════════════════════════
#  SCENE 5 — diagnose
# ══════════════════════════════════════════════════════════════
Type "devsecops diagnose"
Sleep 400ms
Enter
Sleep 3500ms

Sleep 4s
