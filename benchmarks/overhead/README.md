# @toolveto/benchmarks-overhead

Open, reproducible latency and throughput overhead benchmarks for `@toolveto/shield` and `toolveto-gateway`.

## Running Local Overhead Test

```bash
pnpm --filter @toolveto/benchmarks-overhead run bench
```

## Running k6 Load Test (500 RPS)

```bash
k6 run k6-shield-overhead.js
```
