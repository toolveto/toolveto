# Multi-stage build for ToolVeto Gateway
FROM node:22-alpine AS builder

WORKDIR /app
RUN corepack enable && corepack prepare pnpm@10.5.2 --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json tsconfig.base.json tsconfig.json ./
COPY packages/core ./packages/core
COPY packages/shield ./packages/shield
COPY packages/gateway ./packages/gateway

RUN pnpm install --frozen-lockfile
RUN pnpm --filter @toolveto/core run build
RUN pnpm --filter @toolveto/shield run build
RUN pnpm --filter toolveto-gateway run build
RUN pnpm --filter toolveto-gateway --legacy deploy --prod /app/deployed-gateway || pnpm --filter toolveto-gateway deploy --prod /app/deployed-gateway

FROM node:22-alpine AS runner
LABEL org.opencontainers.image.source="https://github.com/toolveto/toolveto"
LABEL org.opencontainers.image.description="ToolVeto Runtime Shield MCP Gateway (Sub-2ms Idempotency, Loop Breaker & Rug-Pull Firewall)"
LABEL org.opencontainers.image.licenses="MIT"
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8080
ENV RUN_STANDALONE=true

COPY --from=builder --chown=0:0 /app/deployed-gateway ./
COPY --chown=0:0 toolveto-gateway.yml ./toolveto-gateway.yml
RUN chmod -R a-w /app && rm -f /bin/sh /bin/ash

USER node
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8080/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

ENTRYPOINT ["node"]
CMD ["dist/index.js"]
