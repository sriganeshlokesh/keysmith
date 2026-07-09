# syntax=docker/dockerfile:1

# ── Builder ────────────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS builder

WORKDIR /src

# Layer cache: dependencies change less often than source code.
# The go.work workspace spans the root module and pkg/authkit.
COPY go.mod go.sum go.work go.work.sum ./
COPY pkg/authkit/go.mod ./pkg/authkit/
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X github.com/sriganeshlokesh/keysmith/config.Version=${VERSION}" \
    -o /out/keysmith \
    ./cmd

# ── Final image ────────────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/keysmith /keysmith

# EXPOSE is documentation only — Railway routes to the value of $PORT at runtime.
EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/keysmith"]
