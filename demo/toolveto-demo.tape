# ToolVeto Deterministic CI Gate & Invariant Engine Demo
# Built for charmbracelet/vhs (https://github.com/charmbracelet/vhs)
# Generates high-density terminal demo for GitHub README and documentation

Output demo/toolveto-demo.gif
Output demo/toolveto-demo.webm

Set Shell "bash"
Set FontSize 15
Set FontFamily "JetBrains Mono"
Set Width 1200
Set Height 680
Set Theme "TokyoNight"
Set Padding 24
Set WindowBar "Colorful"
Set WindowBarSize 36
Set TypingSpeed 45ms

# Initial prompt
Sleep 1s
Type "npx toolveto check stdio://servers/stripe-billing-mcp"
Sleep 600ms
Enter

# Wait for 12-check battery run and Fatal Veto display
Sleep 3.5s

# Notice fatal veto and inspect AST patch
Type "# Invariant Violation: Non-Idempotent Mutation Detected ($Φ = 1.00)"
Sleep 500ms
Enter
Sleep 1s

# Run automated AST fix
Type "npx toolveto fix stdio://servers/stripe-billing-mcp --apply"
Sleep 600ms
Enter

# Wait for AST patch application
Sleep 2.5s

# Re-run check to verify 100/100 score and JWS attestation minting
Type "npx toolveto check stdio://servers/stripe-billing-mcp --mint"
Sleep 600ms
Enter

Sleep 3.5s
