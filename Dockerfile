# syntax=docker/dockerfile:1

FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:24-bookworm-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund \
    && npm cache clean --force
COPY --from=build /app/src ./src
COPY --from=build /app/tsconfig.json ./tsconfig.json
RUN mkdir -p /data && chown node:node /data
USER node
EXPOSE 8883
CMD ["npm", "start"]
