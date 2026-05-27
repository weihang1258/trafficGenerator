# Build stage - Frontend
FROM node:18-alpine AS frontend-builder

WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
RUN npm install
COPY web/ ./
RUN npm run build

# Build stage - Backend
FROM golang:1.21-alpine AS backend-builder

RUN apk add --no-cache git make gcc musl-dev libpcap-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Copy frontend dist into web/dist for static file serving
COPY --from=frontend-builder /app/web/dist ./web/dist

RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-w -s" -o /trafficgen ./cmd/server

# Final stage
FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata libpcap

RUN adduser -D -g '' appuser

WORKDIR /app
COPY --from=backend-builder /trafficgen /app/trafficgen
COPY configs/config.yaml /app/configs/config.yaml
COPY --from=backend-builder /app/web/dist /app/web/dist

RUN mkdir -p /app/data /var/log/trafficgen && chown -R appuser:appuser /app

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/trafficgen"]
CMD ["-config", "/app/configs/config.yaml"]
