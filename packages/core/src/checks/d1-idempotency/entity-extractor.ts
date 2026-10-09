import crypto from 'node:crypto';

/**
 * Deep recursive entity identity extractor.
 * Discovers entity identity across varied API paradigms (charge_id, orderId, paymentId, uuid, key, etc.)
 * or generates a deterministic canonical state fingerprint.
 */
export function extractEntityId(obj: any): string | null {
  if (obj === null || typeof obj !== 'object') {
    return null;
  }

  // 1. Check known top-level entity ID keys
  const topKeys = [
    'charge_id', 'payment_id', 'order_id', 'transaction_id', 'tx_id',
    'invoice_id', 'receipt_id', 'subscription_id', 'refund_id', 'customer_id',
    'user_id', 'account_id', 'item_id', 'record_id', 'entity_id', 'id', 'uuid', 'key'
  ];

  for (const k of topKeys) {
    if (obj[k] != null && typeof obj[k] !== 'object') {
      return String(obj[k]);
    }
  }

  // Check nested charge or payment objects (e.g. parsed.charge.charge_id)
  if (obj.charge && typeof obj.charge === 'object') {
    if (obj.charge.charge_id != null) return String(obj.charge.charge_id);
    if (obj.charge.id != null) return String(obj.charge.id);
    if (obj.charge.total_mutations_on_server != null) {
      return `mutation_${obj.charge.total_mutations_on_server}`;
    }
  }
  if (obj.payment && typeof obj.payment === 'object') {
    if (obj.payment.payment_id != null) return String(obj.payment.payment_id);
    if (obj.payment.id != null) return String(obj.payment.id);
  }

  // 2. Deep recursive search for any field ending in _id, Id, _uuid, _key
  const queue: any[] = [obj];
  const visited = new WeakSet();

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current || typeof current !== 'object' || visited.has(current)) continue;
    visited.add(current);

    for (const [k, v] of Object.entries(current)) {
      if (v != null && typeof v !== 'object') {
        const lower = k.toLowerCase();
        if (
          lower.endsWith('_id') ||
          (lower.endsWith('id') && lower.length > 2) ||
          lower.endsWith('_uuid') ||
          lower.endsWith('_key') ||
          lower.includes('reference') ||
          lower.includes('receipt') ||
          lower.includes('tracking')
        ) {
          return String(v);
        }
      } else if (v && typeof v === 'object') {
        queue.push(v);
      }
    }
  }

  return null;
}

/**
 * Deterministic canonical JSON hash excluding non-deterministic volatile fields
 * (timestamps, latency, random tokens, volatile counters).
 */
export function hashPayloadState(text: string): string {
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === 'object') {
      const sanitized = { ...parsed };
      delete sanitized.timestamp;
      delete sanitized.time;
      delete sanitized.date;
      delete sanitized.duration;
      delete sanitized.latency;
      delete sanitized.nonce;
      return crypto.createHash('sha256').update(JSON.stringify(sanitized)).digest('hex').slice(0, 16);
    }
  } catch {
    // Non-JSON
  }
  return crypto.createHash('sha256').update(text.trim()).digest('hex').slice(0, 16);
}
