# ============================================================================
# ToolVeto Auto-Generated Least-Privilege Open Policy Agent (Rego) Policy
# Standard: AIUC-1 §5.1 & OWASP Agentic Least Agency
# ============================================================================
package toolveto.authz

import rego.v1

default allow := false

read_only_tools := ["list_projects"]
mutation_tools := ["run_sql_query","create_branch"]
destructive_tools := ["delete_branch"]

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
