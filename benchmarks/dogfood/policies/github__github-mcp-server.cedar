// ============================================================================
// ToolVeto Auto-Generated Least-Privilege AWS Cedar Policy
// Standard: AIUC-1 §5.1 & OWASP Agentic Least Agency
// ============================================================================

// Tool 'create_issue' (State Mutation — requires idempotency key)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"create_issue"
) when {
  context.hasIdempotencyKey == true
};

// Tool 'get_issue' (Read-Only Query — safe for autonomous execution)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"get_issue"
);

// Tool 'list_pull_requests' (Read-Only Query — safe for autonomous execution)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"list_pull_requests"
);

// Tool 'merge_pull_request' (State Mutation — requires idempotency key)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"merge_pull_request"
) when {
  context.hasIdempotencyKey == true
};
