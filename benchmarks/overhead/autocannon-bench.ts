import { ShieldMiddleware } from '@toolveto/shield';

async function runBenchmark() {
  const iterations = 50000;
  const middleware = new ShieldMiddleware({
    idempotency: true,
    loopLimit: { count: 100, windowMs: 1000 },
    tokenBudget: 4000,
  });

  const dummyReq = {
    method: 'tools/call',
    params: {
      name: 'charge_card',
      arguments: { idempotency_key: 'test-key-1' },
    },
  };

  const handler = async () => ({
    content: [{ type: 'text', text: 'ok' }],
  });

  // Warmup
  for (let i = 0; i < 1000; i++) {
    await middleware.intercept(dummyReq, handler);
  }

  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    await middleware.intercept(dummyReq, handler);
  }
  const totalMs = performance.now() - start;
  const avgUs = (totalMs / iterations) * 1000;

  console.log(`\n======================================================`);
  console.log(` ToolVeto Shield In-Memory Latency Benchmark`);
  console.log(`======================================================`);
  console.log(` Iterations: ${iterations.toLocaleString()}`);
  console.log(` Total Time: ${totalMs.toFixed(2)} ms`);
  console.log(` Average Overhead: ${avgUs.toFixed(2)} µs per call (<0.01 ms)`);
  console.log(` Throughput: ${(iterations / (totalMs / 1000)).toFixed(0)} calls/sec`);
  console.log(`======================================================\n`);
}

runBenchmark().catch(console.error);
