// ============================================================================
// ToolVeto Auto-Generated Least-Privilege AWS Cedar Policy
// Standard: AIUC-1 §5.1 & OWASP Agentic Least Agency
// ============================================================================

// Tool 'create_payment_intent' (State Mutation — requires idempotency key)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"create_payment_intent"
) when {
  context.hasIdempotencyKey == true
};

// Tool 'create_customer' (State Mutation — requires idempotency key)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"create_customer"
) when {
  context.hasIdempotencyKey == true
};

// Tool 'list_charges' (Read-Only Query — safe for autonomous execution)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"list_charges"
);

// Tool 'refund_charge' (State Mutation — requires idempotency key)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"refund_charge"
) when {
  context.hasIdempotencyKey == true
};
