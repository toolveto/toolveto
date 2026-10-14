// ============================================================================
// ToolVeto Auto-Generated Least-Privilege AWS Cedar Policy
// Standard: AIUC-1 §5.1 & OWASP Agentic Least Agency
// ============================================================================

// Tool 'fetch' (Read-Only Query — safe for autonomous execution)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"fetch"
);

// Tool 'filesystem_read_file' (Read-Only Query — safe for autonomous execution)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"filesystem_read_file"
);

// Tool 'filesystem_write_file' (State Mutation — requires idempotency key)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"filesystem_write_file"
) when {
  context.hasIdempotencyKey == true
};

// Tool 'git_create_commit' (State Mutation — requires idempotency key)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"git_create_commit"
) when {
  context.hasIdempotencyKey == true
};

// Tool 'git_status' (Read-Only Query — safe for autonomous execution)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"git_status"
);
