FROM node:22-alpine AS builder

WORKDIR /app
RUN npm install -g pnpm

COPY package.json pnpm-workspace.yaml turbo.json tsconfig.base.json tsconfig.json ./
COPY packages/core ./packages/core
COPY packages/shield ./packages/shield
COPY packages/gateway ./packages/gateway

RUN pnpm install --frozen-lockfile || pnpm install
RUN pnpm --filter toolveto-gateway run build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8080

COPY --from=builder /app/packages/gateway/dist ./dist
COPY --from=builder /app/packages/gateway/package.json ./package.json

EXPOSE 8080
USER node
CMD ["node", "dist/index.js"]
