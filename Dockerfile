# syntax=docker/dockerfile:1

# ---- build -----------------------------------------------------------------
# Base images are pinned by digest for reproducible, tamper-evident builds.
# Update with: docker buildx imagetools inspect golang:1.27.4-alpine
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=unknown
RUN go build -ldflags "-s -w -buildid= -X main.version=${VERSION}" -o /out/mdmail ./cmd/mdmail \
 && mkdir -p /out/data

# ---- runtime ---------------------------------------------------------------
# distroless/static: no shell, no package manager, CA certificates + tzdata only.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
LABEL org.opencontainers.image.title="mdmail" \
      org.opencontainers.image.description="Self-hosted email server with Markdown-authored mail" \
      org.opencontainers.image.source="https://github.com/t-el/mdmail" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/mdmail /usr/local/bin/mdmail
COPY --from=build --chown=65532:65532 --chmod=0700 /out/data /data
# Unprivileged ports inside the container; map 25/587/465/443/80 on the host.
ENV MDMAIL_DATA_DIR=/data \
    MDMAIL_SMTP_ADDR=:2525 \
    MDMAIL_SUBMISSION_ADDR=:5870 \
    MDMAIL_SUBMISSIONS_ADDR=:4650 \
    MDMAIL_HTTPS_ADDR=:8443 \
    MDMAIL_HTTP_ADDR=:8080 \
    MDMAIL_HEALTH_ADDR=127.0.0.1:9090
USER 65532:65532
EXPOSE 2525 5870 4650 8443 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["/usr/local/bin/mdmail", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/mdmail"]
CMD ["serve"]
