import http from 'k6/http';
import { check } from 'k6';

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
    shielded_proxy: {
      executor: 'constant-arrival-rate',
      rate: 500,
      timeUnit: '1s',
      duration: '30s',
      preAllocatedVUs: 20,
      maxVUs: 50,
      exec: 'testShielded',
      startTime: '35s',
    },
  },
  thresholds: {
    'http_req_duration{scenario:shielded_proxy}': ['p(95)<15', 'p(99)<25'], // strict SLA on proxy latency
  },
};

const payload = JSON.stringify({
  jsonrpc: '2.0',
  id: 'bench-1',
  method: 'tools/call',
  params: {
    name: 'create_payment',
    arguments: {
      amount: 100,
      currency: 'USD',
      idempotency_key: 'bench-key-fixed',
    },
  },
});

export function testBaseline() {
  const res = http.post('http://localhost:3000/mcp', payload, {
    headers: { 'Content-Type': 'application/json' },
  });
  check(res, { 'status is 200': (r) => r.status === 200 });
}

export function testShielded() {
  const res = http.post('http://localhost:8080/mcp', payload, {
    headers: { 'Content-Type': 'application/json' },
  });
  check(res, { 'status is 200': (r) => r.status === 200 });
}
