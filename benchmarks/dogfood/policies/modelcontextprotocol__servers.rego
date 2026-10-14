# ============================================================================
# ToolVeto Auto-Generated Least-Privilege Open Policy Agent (Rego) Policy
# Standard: AIUC-1 §5.1 & OWASP Agentic Least Agency
# ============================================================================
package toolveto.authz

import rego.v1

default allow := false

read_only_tools := ["fetch","filesystem_read_file","git_status"]
mutation_tools := ["filesystem_write_file","git_create_commit"]
destructive_tools := []

# Allow read-only inspection tools unconditionally
allow if {
  input.method == "tools/call"
  input.params.name in read_only_tools
}

# Allow standard state mutations only when idempotency_key is provided
allow if {
  input.method == "tools/call"
  input.params.name in mutation_tools
  input.params.arguments.idempotency_key != ""
}

# Allow destructive tools only with explicit human-in-the-loop approval
allow if {
  input.method == "tools/call"
  input.params.name in destructive_tools
  input.context.human_approved == true
}
