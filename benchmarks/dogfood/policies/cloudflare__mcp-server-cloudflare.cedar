// ============================================================================
// ToolVeto Auto-Generated Least-Privilege AWS Cedar Policy
// Standard: AIUC-1 §5.1 & OWASP Agentic Least Agency
// ============================================================================

// Tool 'deploy_worker' (State Mutation — requires idempotency key)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"deploy_worker"
) when {
  context.hasIdempotencyKey == true
};

// Tool 'purge_cache' (Destructive Mutation — requires human approval)
forbid (
  principal,
  action == Action::"tools/call",
  resource == Tool::"purge_cache"
) unless {
  context.humanApproved == true
};

// Tool 'list_dns_records' (Read-Only Query — safe for autonomous execution)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"list_dns_records"
);

// Tool 'update_dns_record' (State Mutation — requires idempotency key)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"update_dns_record"
) when {
  context.hasIdempotencyKey == true
};
