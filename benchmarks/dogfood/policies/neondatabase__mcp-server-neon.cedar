// ============================================================================
// ToolVeto Auto-Generated Least-Privilege AWS Cedar Policy
// Standard: AIUC-1 §5.1 & OWASP Agentic Least Agency
// ============================================================================

// Tool 'run_sql_query' (State Mutation — requires idempotency key)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"run_sql_query"
) when {
  context.hasIdempotencyKey == true
};

// Tool 'create_branch' (State Mutation — requires idempotency key)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"create_branch"
) when {
  context.hasIdempotencyKey == true
};

// Tool 'delete_branch' (Destructive Mutation — requires human approval)
forbid (
  principal,
  action == Action::"tools/call",
  resource == Tool::"delete_branch"
) unless {
  context.humanApproved == true
};

// Tool 'list_projects' (Read-Only Query — safe for autonomous execution)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"list_projects"
);
