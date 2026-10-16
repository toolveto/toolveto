import http from 'k6/http';
import { check } from 'k6';
import exec from 'k6/execution';
import { Trend } from 'k6/metrics';

const shieldAirbagLatency = new Trend('shield_airbag_latency_ms', true);

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
    'http_req_duration{scenario:shielded_cache_miss}': ['p(50)<5', 'p(95)<15', 'p(99)<25'],
    'http_req_duration{scenario:shielded_cache_hit}': ['p(50)<2', 'p(95)<5', 'p(99)<10'],
    shield_airbag_latency_ms: ['p(50)<1.8', 'p(95)<1.8'],
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
    headers: { 'Content-Type': 'application/json' },
  });
  recordAirbagHeader(res);
  check(res, {
    'status is 200': (r) => r.status === 200,
    'action is PASS': (r) => (r.headers['X-Toolveto-Action'] || r.headers['x-toolveto-action']) === 'PASS',
  });
}

export function testShieldedHit() {
  const res = http.post('http://localhost:8080/mcp', buildPayload('k-0'), {
    headers: { 'Content-Type': 'application/json' },
  });
  recordAirbagHeader(res);
  check(res, {
    'status is 200': (r) => r.status === 200,
  });
}

