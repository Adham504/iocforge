# ============================================================================
# IOCForge — VHS demo script (.tape)
# ----------------------------------------------------------------------------
# Renders a polished terminal GIF showing the full flow:
#   banner -> analyze -> summary -> reports -> open HTML report
#
# HOW TO RUN (one command):
#   1) Install VHS:        https://github.com/charmbracelet/vhs
#        macOS:   brew install vhs
#        Linux:   go install github.com/charmbracelet/vhs@latest   (or download a release)
#   2) From the project root, run:
#        vhs docs/demo.tape
#   3) Output is written to:  docs/img/demo.gif
#
# Tip: run inside your activated venv so `iocforge` is on PATH.
# ============================================================================

# ---- Output ----------------------------------------------------------------
Output docs/img/demo.gif

# ---- Look & feel -----------------------------------------------------------
Set Theme "Dracula"
Set FontSize 18
Set Width 1200
Set Height 760
Set Padding 24
Set TypingSpeed 55ms
Set PlaybackSpeed 1.0
Set Margin 16
Set MarginFill "#0f1419"
Set BorderRadius 10

# ---- Scene 1: title --------------------------------------------------------
Type "# IOCForge — Extract • Analyze • Enrich • Understand"
Sleep 800ms
Enter
Sleep 1s

# ---- Scene 2: show the banner + capabilities -------------------------------
Type "iocforge info"
Sleep 500ms
Enter
Sleep 3s

# ---- Scene 3: analyze a sample threat report -------------------------------
Type "iocforge analyze examples/sample_report.txt --no-enrich -q"
Sleep 600ms
Enter
Sleep 4s

# Let the summary breathe so viewers can read the IOC counts.
Sleep 2s

# ---- Scene 4: peek at the generated reports --------------------------------
Type "ls reports/"
Sleep 400ms
Enter
Sleep 2s

# ---- Scene 5: open the interactive HTML dashboard --------------------------
Type "# Open the HTML dashboard in your browser:"
Sleep 500ms
Enter
Type "open reports/iocforge_report.html   # macOS  (Linux: xdg-open, Windows: start)"
Sleep 800ms
Enter
Sleep 2s

# ---- Scene 6: closing line -------------------------------------------------
Type "# ✓ 21 IOCs extracted, cleaned & reported — false positives auto-removed."
Sleep 600ms
Enter
Sleep 2500ms
