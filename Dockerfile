# syntax=docker/dockerfile:1

FROM node:24-bookworm-slim AS builder

WORKDIR /app

COPY package.json package-lock.json tsconfig.base.json ./
COPY packages ./packages
COPY web/package.json web/package-lock.json ./web/

RUN npm ci
RUN npm --prefix web ci

COPY web ./web
COPY scripts ./scripts

RUN npm run typecheck
RUN npm --prefix web run build
RUN npm prune --omit=dev
RUN npm --prefix web prune --omit=dev

FROM node:24-bookworm-slim AS runner

ENV NODE_ENV=production
ENV PORT=3001
ENV ARGUS_API_PORT=8089
ENV ARGUS_API=http://127.0.0.1:8089
ENV ARGUS_DATA_DIR=/data
ENV ARGUS_DB_PATH=/data/argus.sqlite

WORKDIR /app

RUN mkdir -p /data

COPY --from=builder /app/package.json /app/package-lock.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages ./packages
COPY --from=builder /app/scripts ./scripts
COPY --from=builder /app/web/package.json /app/web/package-lock.json ./web/
COPY --from=builder /app/web/node_modules ./web/node_modules
COPY --from=builder /app/web/.next ./web/.next
COPY --from=builder /app/web/public ./web/public
COPY --from=builder /app/web/next.config.mjs ./web/next.config.mjs

EXPOSE 3001
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["node", "scripts/healthcheck.mjs"]

CMD ["npm", "start"]
