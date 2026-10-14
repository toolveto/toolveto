// ============================================================================
// ToolVeto Auto-Generated Least-Privilege AWS Cedar Policy
// Standard: AIUC-1 §5.1 & OWASP Agentic Least Agency
// ============================================================================

// Tool 'create_page' (State Mutation — requires idempotency key)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"create_page"
) when {
  context.hasIdempotencyKey == true
};

// Tool 'get_page' (Read-Only Query — safe for autonomous execution)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"get_page"
);

// Tool 'update_page' (State Mutation — requires idempotency key)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"update_page"
) when {
  context.hasIdempotencyKey == true
};

// Tool 'search_content' (Read-Only Query — safe for autonomous execution)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"search_content"
);
