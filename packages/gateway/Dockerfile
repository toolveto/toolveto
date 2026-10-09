# Multi-stage build for ToolVeto Gateway
FROM node:22-alpine AS builder

WORKDIR /app
RUN npm install -g pnpm@10.5.2

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json tsconfig.base.json tsconfig.json ./
COPY packages/core ./packages/core
COPY packages/shield ./packages/shield
COPY packages/gateway ./packages/gateway

RUN pnpm install --frozen-lockfile || pnpm install
RUN pnpm --filter @toolveto/core run build
RUN pnpm --filter @toolveto/shield run build
RUN pnpm --filter toolveto-gateway run build
RUN pnpm --filter toolveto-gateway deploy --prod /app/deployed-gateway

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8080
ENV RUN_STANDALONE=true

COPY --from=builder /app/deployed-gateway ./
COPY toolveto-gateway.yml ./toolveto-gateway.yml

USER node
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8080/health || exit 1

CMD ["node", "dist/index.js"]
