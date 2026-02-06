# Multi-stage build for AI Authority
FROM node:20-alpine AS base
RUN corepack enable && corepack prepare pnpm@8.15.0 --activate
WORKDIR /app

# Dependencies stage
FROM base AS deps
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml* ./
COPY packages/core/package.json packages/core/
COPY packages/detection/package.json packages/detection/
COPY packages/scoring/package.json packages/scoring/
COPY packages/federation/package.json packages/federation/
COPY packages/adjudication/package.json packages/adjudication/
COPY packages/intervention/package.json packages/intervention/
COPY packages/dashboard/package.json packages/dashboard/
RUN pnpm install --frozen-lockfile

# Build stage
FROM base AS builder
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/packages/*/node_modules ./packages/
COPY . .
RUN pnpm build

# Dashboard production stage
FROM nginx:alpine AS dashboard
COPY --from=builder /app/packages/dashboard/dist /usr/share/nginx/html
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

# API server stage (placeholder for future API)
FROM base AS api
COPY --from=builder /app/packages/*/dist ./packages/
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
EXPOSE 4000
CMD ["node", "packages/api/dist/index.js"]

# Development stage
FROM base AS development
COPY package.json pnpm-workspace.yaml ./
COPY packages/*/package.json ./packages/
RUN pnpm install
COPY . .
EXPOSE 3000 4000
CMD ["pnpm", "dev"]
