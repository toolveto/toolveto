import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { ShieldMiddleware } from '@toolveto/shield';

function percentile(sortedUs: number[], p: number): number {
  if (sortedUs.length === 0) return 0;
  const idx = Math.min(sortedUs.length - 1, Math.floor((p / 100) * sortedUs.length));
  return sortedUs[idx];
}

function summarizeUs(samplesUs: number[], totalMs: number) {
  const sorted = [...samplesUs].sort((a, b) => a - b);
  return {
    iterations: samplesUs.length,
    totalMs: Number(totalMs.toFixed(3)),
    p50Ms: Number((percentile(sorted, 50) / 1000).toFixed(4)),
    p95Ms: Number((percentile(sorted, 95) / 1000).toFixed(4)),
    p99Ms: Number((percentile(sorted, 99) / 1000).toFixed(4)),
    callsPerSec: Math.round(samplesUs.length / Math.max(totalMs / 1000, 0.0001)),
  };
}

function postJson(
  agent: http.Agent,
  port: number,
  bodyStr: string
): Promise<{ status: number; airbagMs: number | null; action: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: '/mcp',
        method: 'POST',
        agent,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(bodyStr),
        },
      },
      (res) => {
        res.resume();
        res.on('end', () => {
          const hdrLatency = res.headers['x-toolveto-airbag-latency'];
          const airbagMs = hdrLatency ? parseFloat(String(hdrLatency)) : null;
          const action = String(res.headers['x-toolveto-action'] || '');
          resolve({
            status: res.statusCode || 0,
            airbagMs: Number.isFinite(airbagMs) ? airbagMs : null,
            action,
          });
        });
      }
    );
    req.on('error', reject);
    req.write(bodyStr);
    req.end();
  });
}

async function runLiveHttpProxyBenchmark() {
  let burstUpstreamExecutions = 0;

  const upstreamServer = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const bodyStr = Buffer.concat(chunks).toString('utf8');
      let parsed: any = {};
      try {
        parsed = JSON.parse(bodyStr || '{}');
      } catch {}
      const orderId = parsed?.params?.arguments?.order_id;
      const finish = () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: parsed?.id || 1,
            result: { content: [{ type: 'text', text: `{"status":"ok","order":"${orderId || 'none'}"}` }] },
          })
        );
      };
      if (orderId === 'burst-shared') {
        burstUpstreamExecutions++;
        setTimeout(finish, 10);
      } else {
        finish();
      }
    });
  });

  await new Promise<void>((resolve) => upstreamServer.listen(0, '127.0.0.1', resolve));
  const upstreamPort = (upstreamServer.address() as any).port;
  const upstreamAgent = new http.Agent({ keepAlive: true, maxSockets: 64 });

  const proxyShield = new ShieldMiddleware({
    idempotency: true,
    failClosed: true,
    loopLimit: { count: 100000, windowMs: 60000 },
    promptInjectionScan: { action: 'block', scanOutput: true },
    tokenBudget: 4000,
  });

  const proxyServer = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      try {
        const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
        const t0 = process.hrtime.bigint();
        const result = await proxyShield.intercept(parsed, () => {
          return new Promise<any>((resolve, reject) => {
            const payload = JSON.stringify(parsed);
            const upReq = http.request(
              {
                hostname: '127.0.0.1',
                port: upstreamPort,
                path: '/mcp',
                method: 'POST',
                agent: upstreamAgent,
                headers: {
                  'Content-Type': 'application/json',
                  'Content-Length': Buffer.byteLength(payload),
                },
              },
              (upRes) => {
                const upChunks: Buffer[] = [];
                upRes.on('data', (c) => upChunks.push(c));
                upRes.on('end', () => {
                  try {
                    const upJson = JSON.parse(Buffer.concat(upChunks).toString('utf8'));
                    resolve(upJson.result);
                  } catch (e) {
                    reject(e);
                  }
                });
              }
            );
            upReq.on('error', reject);
            upReq.write(payload);
            upReq.end();
          });
        });
        const elapsedMs = Number(process.hrtime.bigint() - t0) / 1_000_000;
        const action = result.isError ? 'VETO' : result._shield?.cached ? 'DEDUPLICATED' : 'PASS';
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'X-ToolVeto-Action': action,
          'X-ToolVeto-Airbag-Latency': elapsedMs.toFixed(4),
        });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: parsed?.id || 1, result }));
      } catch (err: any) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err?.message || 'Proxy failure' }));
      }
    });
  });

  await new Promise<void>((resolve) => proxyServer.listen(0, '127.0.0.1', resolve));
  const proxyPort = (proxyServer.address() as any).port;
  const clientAgent = new http.Agent({ keepAlive: true, maxSockets: 64 });

  try {
    // 1. Live concurrent HTTP proxy load (2,000 calls @ concurrency 50)
    const loadTotal = 2000;
    const concurrency = 50;
    const endToEndUs: number[] = [];
    const airbagUs: number[] = [];
    let failedCalls = 0;

    let nextIdx = 0;
    const loadStart = process.hrtime.bigint();
    const workers = Array.from({ length: concurrency }, async () => {
      while (true) {
        const idx = nextIdx++;
        if (idx >= loadTotal) break;
        const payload = JSON.stringify({
          jsonrpc: '2.0',
          id: `http-${idx}`,
          method: 'tools/call',
          params: {
            name: 'charge_card',
            arguments: {
              order_id: `ord-${idx}`,
              amount: 100 + (idx % 25),
              currency: 'USD',
              idempotency_key: `http-k-${idx % 1000}`,
            },
          },
        });
        const t0 = process.hrtime.bigint();
        const r = await postJson(clientAgent, proxyPort, payload);
        const dtUs = Number(process.hrtime.bigint() - t0) / 1000;
        endToEndUs.push(dtUs);
        if (r.status !== 200) failedCalls++;
        if (r.airbagMs !== null && r.action === 'DEDUPLICATED') {
          airbagUs.push(r.airbagMs * 1000);
        }
      }
    });
    await Promise.all(workers);
    const loadTotalMs = Number(process.hrtime.bigint() - loadStart) / 1_000_000;
    if (failedCalls > 0) {
      throw new Error(`Live HTTP proxy load recorded ${failedCalls} non-200 responses`);
    }

    // 2. Live HTTP 100-way simultaneous duplicate charge thundering herd
    const burstCount = 100;
    const burstPayload = JSON.stringify({
      jsonrpc: '2.0',
      id: 'burst-req',
      method: 'tools/call',
      params: {
        name: 'charge_card',
        arguments: {
          order_id: 'burst-shared',
          amount: 4500,
          currency: 'USD',
          idempotency_key: 'http-burst-001',
        },
      },
    });
    const burstStart = process.hrtime.bigint();
    const burstResponses = await Promise.all(
      Array.from({ length: burstCount }, () => postJson(clientAgent, proxyPort, burstPayload))
    );
    const burstTotalMs = Number(process.hrtime.bigint() - burstStart) / 1_000_000;
    const burstOkCount = burstResponses.filter((r) => r.status === 200).length;
    if (burstUpstreamExecutions !== 1 || burstOkCount !== burstCount) {
      throw new Error(
        `Expected exact-once upstream execution on HTTP 100-way burst, got upstreamExecutions=${burstUpstreamExecutions}, okCount=${burstOkCount}`
      );
    }

    return {
      liveHttpProxyLoad: {
        concurrency,
        failedCalls,
        endToEnd: summarizeUs(endToEndUs, loadTotalMs),
        shieldDedupOverhead: summarizeUs(airbagUs.length > 0 ? airbagUs : [0], loadTotalMs),
      },
      liveHttpThunderingHerd: {
        simultaneousRequests: burstCount,
        http200Count: burstOkCount,
        upstreamExecutions: burstUpstreamExecutions,
        duplicatesPrevented: burstCount - burstUpstreamExecutions,
        totalMs: Number(burstTotalMs.toFixed(2)),
      },
    };
  } finally {
    clientAgent.destroy();
    upstreamAgent.destroy();
    await Promise.all([
      new Promise<void>((resolve) => proxyServer.close(() => resolve())),
      new Promise<void>((resolve) => upstreamServer.close(() => resolve())),
    ]);
  }
}

function getJsonOutPath(): string | undefined {
  const idx = process.argv.indexOf('--json-out');
  if (idx !== -1 && idx + 1 < process.argv.length) {
    return process.argv[idx + 1];
  }
  return process.env.BENCHMARK_JSON_OUT || undefined;
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
  const missSummary = summarizeUs(missLatenciesUs, missTotalMs);

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
  const hitSummary = summarizeUs(hitLatenciesUs, hitTotalMs);

  // 3. Live TCP/HTTP Proxy Concurrency + 100-Way Thundering Herd
  const httpBench = await runLiveHttpProxyBenchmark();

  console.log(`\n================================================================`);
  console.log(` ToolVeto Shield Latency & Concurrency Benchmark`);
  console.log(`================================================================`);
  console.log(` [In-Memory Cache-Miss Path: Unique keys k-0..k-${iterations - 1}]`);
  console.log(`   Iterations: ${iterations.toLocaleString()} | Total: ${missSummary.totalMs.toFixed(2)} ms`);
  console.log(`   p50: ${missSummary.p50Ms.toFixed(4)} ms | p95: ${missSummary.p95Ms.toFixed(4)} ms | p99: ${missSummary.p99Ms.toFixed(4)} ms`);
  console.log(`   Throughput: ${missSummary.callsPerSec} calls/sec`);
  console.log(`----------------------------------------------------------------`);
  console.log(` [In-Memory Cache-Hit Path: Deduplicated Replay]`);
  console.log(`   Iterations: ${iterations.toLocaleString()} | Total: ${hitSummary.totalMs.toFixed(2)} ms`);
  console.log(`   p50: ${hitSummary.p50Ms.toFixed(4)} ms | p95: ${hitSummary.p95Ms.toFixed(4)} ms | p99: ${hitSummary.p99Ms.toFixed(4)} ms`);
  console.log(`   Throughput: ${hitSummary.callsPerSec} calls/sec`);
  console.log(`----------------------------------------------------------------`);
  console.log(` [Live TCP/HTTP Proxy Load: ${httpBench.liveHttpProxyLoad.endToEnd.iterations.toLocaleString()} calls @ c=${httpBench.liveHttpProxyLoad.concurrency}]`);
  console.log(
    `   E2E p50: ${httpBench.liveHttpProxyLoad.endToEnd.p50Ms.toFixed(4)} ms | p95: ${httpBench.liveHttpProxyLoad.endToEnd.p95Ms.toFixed(4)} ms | p99: ${httpBench.liveHttpProxyLoad.endToEnd.p99Ms.toFixed(4)} ms | ${httpBench.liveHttpProxyLoad.endToEnd.callsPerSec} calls/sec`
  );
  console.log(
    `   Live 100-Way Duplicate Charge Burst: upstreamExecutions=${httpBench.liveHttpThunderingHerd.upstreamExecutions}/100 (${httpBench.liveHttpThunderingHerd.duplicatesPrevented} duplicates blocked in ${httpBench.liveHttpThunderingHerd.totalMs} ms)`
  );
  console.log(`================================================================\n`);

  const jsonOut = getJsonOutPath();
  if (jsonOut) {
    const resolved = path.resolve(jsonOut);
    fs.mkdirSync(path.dirname(resolved), { recursive: true });
    fs.writeFileSync(
      resolved,
      JSON.stringify(
        {
          generatedAt: new Date().toISOString(),
          nodeVersion: process.version,
          inMemoryCacheMiss: missSummary,
          inMemoryCacheHit: hitSummary,
          liveHttpProxyLoad: httpBench.liveHttpProxyLoad,
          liveHttpThunderingHerd: httpBench.liveHttpThunderingHerd,
        },
        null,
        2
      ),
      'utf8'
    );
  }

  const SLA_GATE_MS = 1.8;
  if (
    missSummary.p95Ms > SLA_GATE_MS ||
    hitSummary.p95Ms > SLA_GATE_MS ||
    httpBench.liveHttpProxyLoad.shieldDedupOverhead.p95Ms > SLA_GATE_MS
  ) {
    console.error(
      `❌ Latency SLA Gate Failed: p95 overhead (miss=${missSummary.p95Ms.toFixed(3)}ms, hit=${hitSummary.p95Ms.toFixed(3)}ms, httpDedup=${httpBench.liveHttpProxyLoad.shieldDedupOverhead.p95Ms.toFixed(3)}ms) exceeded ${SLA_GATE_MS}ms budget.`
    );
    process.exit(1);
  }
  console.log(`✔ Latency SLA Gate Passed: in-memory and live HTTP Shield overhead within <${SLA_GATE_MS}ms budget.`);
}

runBenchmark().catch((err) => {
  console.error(err);
  process.exit(1);
});

