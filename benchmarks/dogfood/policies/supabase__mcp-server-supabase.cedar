// ============================================================================
// ToolVeto Auto-Generated Least-Privilege AWS Cedar Policy
// Standard: AIUC-1 §5.1 & OWASP Agentic Least Agency
// ============================================================================

// Tool 'execute_sql' (State Mutation — requires idempotency key)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"execute_sql"
) when {
  context.hasIdempotencyKey == true
};

// Tool 'insert_row' (State Mutation — requires idempotency key)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"insert_row"
) when {
  context.hasIdempotencyKey == true
};

// Tool 'update_row' (State Mutation — requires idempotency key)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"update_row"
) when {
  context.hasIdempotencyKey == true
};

// Tool 'list_tables' (Read-Only Query — safe for autonomous execution)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"list_tables"
);
