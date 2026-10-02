# Multi-stage build for minimal image size
FROM golang:1.27-alpine AS builder

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary (ldflags must match cmd/sentinelflow var names)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o sentinelflow \
    ./cmd/sentinelflow

# Runtime stage
FROM alpine:3.23

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    git \
    openssh-client \
    && update-ca-certificates

# Create non-root user
RUN addgroup -S sentinelflow && adduser -S sentinelflow -G sentinelflow

WORKDIR /workspace

# Copy binary from builder
COPY --from=builder /build/sentinelflow /usr/local/bin/sentinelflow

# Copy default policies
COPY policies /policies

# Set ownership
RUN chown -R sentinelflow:sentinelflow /workspace

# Switch to non-root user
USER sentinelflow

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s \
    CMD sentinelflow version || exit 1

# Default command
ENTRYPOINT ["sentinelflow"]
CMD ["--help"]

# Metadata
LABEL org.opencontainers.image.title="SentinelFlow"
LABEL org.opencontainers.image.description="CI/CD Security Gatekeeper"
LABEL org.opencontainers.image.source="https://github.com/cozyGarage/sentielflow"
LABEL org.opencontainers.image.vendor="SentinelFlow"
