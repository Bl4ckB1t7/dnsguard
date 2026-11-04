# syntax=docker/dockerfile:1.7

FROM golang:1.23.3-bookworm AS api-builder
WORKDIR /src/server
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/dnsguard-api .

FROM node:22.12.0-bookworm-slim AS web-builder
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . ./
RUN npm run build

FROM debian:12.8-slim AS api
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends bind9-dnsutils bind9-utils ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 dnsguard \
    && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin dnsguard \
    && install -d -o 10001 -g 10001 -m 0750 /var/lib/dnsguard
COPY --from=api-builder /out/dnsguard-api /usr/local/bin/dnsguard-api
WORKDIR /var/lib/dnsguard
USER 10001:10001
ENV HOME=/nonexistent
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=6 \
    CMD curl --fail --silent http://127.0.0.1:8080/api/health || exit 1
ENTRYPOINT ["/usr/local/bin/dnsguard-api"]

FROM nginx:1.27.3-alpine AS web
COPY --from=web-builder /src/dist /usr/share/nginx/html
COPY deploy/docker/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8443
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=6 \
    CMD wget --no-check-certificate --quiet --spider https://127.0.0.1:8443/ || exit 1
