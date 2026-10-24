# Base images are pinned by digest (multi-arch index); Dependabot keeps the
# digests current.

# The build stage runs on the build machine's own platform and cross-compiles,
# so multi-platform images need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27@sha256:1cfcdb11f37fce9429f617100f39e0251748bbaba454bd431275155701765058 AS build
ARG TARGETOS TARGETARCH TARGETVARIANT
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Static binary with the pure-Go DNS resolver, as distroless/static requires.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags="-s -w -buildid= -X main.version=${VERSION}" -o /out/proxy-acl ./cmd/proxy-acl

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
COPY --from=build /out/proxy-acl /proxy-acl
USER nonroot:nonroot
EXPOSE 3128
# Mount the config *directory* (not the file) so edits that replace the file
# are visible to the hot reload. No config is baked in: without one the
# proxy refuses to start.
ENTRYPOINT ["/proxy-acl"]
CMD ["-config", "/etc/proxy-acl/config.yaml"]
