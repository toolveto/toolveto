import http from 'k6/http';
import { check } from 'k6';
import exec from 'k6/execution';
import { Trend, Counter } from 'k6/metrics';

const shieldAirbagLatency = new Trend('shield_airbag_latency_ms', true);
const shieldAirbagSamples = new Counter('shield_airbag_samples');
const GATEWAY_SECRET = __ENV.TOOLVETO_GATEWAY_SECRET || 'bench-gateway-secret-minimum-32-chars';
const gatewayHeaders = {
  'Content-Type': 'application/json',
  Authorization: `Bearer ${GATEWAY_SECRET}`,
};

export const options = {
  scenarios: {
    baseline_direct: {
      executor: 'constant-arrival-rate',
      rate: 500,
      timeUnit: '1s',
      duration: '30s',
      preAllocatedVUs: 20,
      maxVUs: 50,
      exec: 'testBaseline',
    },
    shielded_cache_miss: {
      executor: 'constant-arrival-rate',
      rate: 500,
      timeUnit: '1s',
      duration: '30s',
      preAllocatedVUs: 20,
      maxVUs: 50,
      exec: 'testShieldedMiss',
      startTime: '35s',
    },
    shielded_cache_hit: {
      executor: 'constant-arrival-rate',
      rate: 500,
      timeUnit: '1s',
      duration: '30s',
      preAllocatedVUs: 20,
      maxVUs: 50,
      exec: 'testShieldedHit',
      startTime: '70s',
    },
  },
  thresholds: {
    http_req_failed: ['rate==0'],
    checks: ['rate==1.0'],
    'http_req_duration{scenario:shielded_cache_miss}': ['p(50)<5', 'p(95)<15', 'p(99)<25'],
    'http_req_duration{scenario:shielded_cache_hit}': ['p(50)<2', 'p(95)<5', 'p(99)<10'],
    shield_airbag_samples: ['count>1000'],
    shield_airbag_latency_ms: ['p(50)>0', 'p(50)<1.8', 'p(95)<1.8'],
  },
};

function buildPayload(idempKey) {
  return JSON.stringify({
    jsonrpc: '2.0',
    id: `bench-${idempKey}`,
    method: 'tools/call',
    params: {
      name: 'create_payment',
      arguments: {
        order_id: idempKey,
        amount: 100,
        currency: 'USD',
        idempotency_key: idempKey,
      },
    },
  });
}

function recordAirbagHeader(res) {
  const hdr = res.headers['X-Toolveto-Airbag-Latency'] || res.headers['x-toolveto-airbag-latency'];
  if (hdr) {
    const val = parseFloat(String(hdr).replace('ms', ''));
    if (!Number.isNaN(val)) {
      shieldAirbagSamples.add(1);
      shieldAirbagLatency.add(val);
    }
  }
}

export function testBaseline() {
  const key = `k-base-${exec.scenario.iterationInTest}`;
  const res = http.post('http://localhost:3000/mcp', buildPayload(key), {
    headers: { 'Content-Type': 'application/json' },
  });
  check(res, { 'status is 200': (r) => r.status === 200 });
}

export function testShieldedMiss() {
  const key = `k-${exec.scenario.iterationInTest}`;
  const res = http.post('http://localhost:8080/mcp', buildPayload(key), {
    headers: gatewayHeaders,
  });
  recordAirbagHeader(res);
  check(res, {
    'status is 200': (r) => r.status === 200,
    'action is PASS': (r) => (r.headers['X-Toolveto-Action'] || r.headers['x-toolveto-action']) === 'PASS',
  });
}

export function testShieldedHit() {
  // Cycle across 6,000 keys (k-8000..k-13999) from the tail window of shielded_cache_miss so
  // every key remains in the 10,000-slot LRU cache and stays strictly under the 5-call loop limit.
  const key = `k-${8000 + (exec.scenario.iterationInTest % 6000)}`;
  const res = http.post('http://localhost:8080/mcp', buildPayload(key), {
    headers: gatewayHeaders,
  });
  recordAirbagHeader(res);
  check(res, {
    'status is 200': (r) => r.status === 200,
    'action is DEDUPLICATED': (r) => (r.headers['X-Toolveto-Action'] || r.headers['x-toolveto-action']) === 'DEDUPLICATED',
  });
}

