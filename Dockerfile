FROM node:24.12.0-alpine

WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY tsconfig.base.json tsconfig.json ./
COPY packages ./packages
COPY apps ./apps
COPY scripts ./scripts

RUN npm exec --yes --package=pnpm@10.13.1 -- pnpm install --frozen-lockfile

EXPOSE 8080

CMD ["node", "apps/server/src/index.ts"]
