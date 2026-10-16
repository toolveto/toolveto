import { ShieldMiddleware } from '@toolveto/shield';

function percentile(sortedUs: number[], p: number): number {
  if (sortedUs.length === 0) return 0;
  const idx = Math.min(sortedUs.length - 1, Math.floor((p / 100) * sortedUs.length));
  return sortedUs[idx];
}

async function runBenchmark() {
  const iterations = 10000;
  const middleware = new ShieldMiddleware({
    idempotency: true,
    loopLimit: { count: 100000, windowMs: 60000 },
    promptInjectionScan: { action: 'block', scanOutput: true },
    tokenBudget: 4000,
  });

  const handler = async () => ({
    content: [{ type: 'text', text: '{"status":"ok","receipt":"ch_live_benchmark"}' }],
  });

  // Warmup
  for (let i = 0; i < 500; i++) {
    await middleware.intercept(
      {
        method: 'tools/call',
        params: {
          name: 'charge_card',
          arguments: { amount: 100, currency: 'USD', idempotency_key: `warmup-${i}` },
        },
      },
      handler
    );
  }

  // 1. Unique-Key Cache-Miss Path (Full canonical hash + prompt injection scan + LRU write)
  const missLatenciesUs: number[] = new Array(iterations);
  const missStart = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    const req = {
      method: 'tools/call',
      params: {
        name: 'charge_card',
        arguments: { amount: 100 + (i % 50), currency: 'USD', idempotency_key: `k-${i}` },
      },
    };
    const t0 = process.hrtime.bigint();
    await middleware.intercept(req, handler);
    const t1 = process.hrtime.bigint();
    missLatenciesUs[i] = Number(t1 - t0) / 1000;
  }
  const missTotalMs = Number(process.hrtime.bigint() - missStart) / 1_000_000;
  missLatenciesUs.sort((a, b) => a - b);

  const missP50Ms = percentile(missLatenciesUs, 50) / 1000;
  const missP95Ms = percentile(missLatenciesUs, 95) / 1000;
  const missP99Ms = percentile(missLatenciesUs, 99) / 1000;

  // 2. Cache-Hit Deduplication Path (Fast idempotent replay interception)
  const hitReq = {
    method: 'tools/call',
    params: {
      name: 'charge_card',
      arguments: { amount: 100, currency: 'USD', idempotency_key: 'k-0' },
    },
  };
  const hitLatenciesUs: number[] = new Array(iterations);
  const hitStart = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    const t0 = process.hrtime.bigint();
    await middleware.intercept(hitReq, handler);
    const t1 = process.hrtime.bigint();
    hitLatenciesUs[i] = Number(t1 - t0) / 1000;
  }
  const hitTotalMs = Number(process.hrtime.bigint() - hitStart) / 1_000_000;
  hitLatenciesUs.sort((a, b) => a - b);

  const hitP50Ms = percentile(hitLatenciesUs, 50) / 1000;
  const hitP95Ms = percentile(hitLatenciesUs, 95) / 1000;
  const hitP99Ms = percentile(hitLatenciesUs, 99) / 1000;

  console.log(`\n================================================================`);
  console.log(` ToolVeto Shield In-Memory Latency Benchmark (Miss vs Hit)`);
  console.log(`================================================================`);
  console.log(` [Cache-Miss Path: Unique keys k-0..k-${iterations - 1}]`);
  console.log(`   Iterations: ${iterations.toLocaleString()} | Total: ${missTotalMs.toFixed(2)} ms`);
  console.log(`   p50: ${missP50Ms.toFixed(4)} ms | p95: ${missP95Ms.toFixed(4)} ms | p99: ${missP99Ms.toFixed(4)} ms`);
  console.log(`   Throughput: ${(iterations / (missTotalMs / 1000)).toFixed(0)} calls/sec`);
  console.log(`----------------------------------------------------------------`);
  console.log(` [Cache-Hit Path: Deduplicated Replay]`);
  console.log(`   Iterations: ${iterations.toLocaleString()} | Total: ${hitTotalMs.toFixed(2)} ms`);
  console.log(`   p50: ${hitP50Ms.toFixed(4)} ms | p95: ${hitP95Ms.toFixed(4)} ms | p99: ${hitP99Ms.toFixed(4)} ms`);
  console.log(`   Throughput: ${(iterations / (hitTotalMs / 1000)).toFixed(0)} calls/sec`);
  console.log(`================================================================\n`);

  const SLA_GATE_MS = 1.8;
  if (missP95Ms > SLA_GATE_MS || hitP95Ms > SLA_GATE_MS) {
    console.error(
      `❌ Latency SLA Gate Failed: p95 overhead (miss=${missP95Ms.toFixed(3)}ms, hit=${hitP95Ms.toFixed(3)}ms) exceeded ${SLA_GATE_MS}ms budget.`
    );
    process.exit(1);
  }
  console.log(`✔ Latency SLA Gate Passed: p95 overhead well within <${SLA_GATE_MS}ms budget.`);
}

runBenchmark().catch((err) => {
  console.error(err);
  process.exit(1);
});

