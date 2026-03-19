# Production Dockerfile for headscale
# Multi-stage build: Go backend + Node.js frontend → minimal runtime image

# ─── Stage 1: Build frontend ──────────────────────────────────────────────────
FROM docker.io/node:22-alpine AS web-builder
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN npm run build

# ─── Stage 2: Build Go binary ─────────────────────────────────────────────────
FROM docker.io/golang:1.26.0-bookworm AS go-builder
ARG VERSION=dev
WORKDIR /go/src/headscale

COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=web-builder /app/web/dist /go/src/headscale/web/dist

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w -X github.com/juanfont/headscale/hscontrol/types.Version=${VERSION}" \
    -o /go/bin/headscale ./cmd/headscale

# ─── Stage 3: Minimal runtime ─────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=go-builder /go/bin/headscale /usr/local/bin/headscale
COPY --from=web-builder /app/web/dist /var/lib/headscale/web-ui

# Default data directory
VOLUME /var/lib/headscale
VOLUME /etc/headscale

EXPOSE 8080 9090 50443 3478/udp

ENTRYPOINT ["headscale"]
CMD ["serve"]
