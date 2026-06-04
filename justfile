set shell := ["bash", "-euo", "pipefail", "-c"]

# abc-auth-svc — routine dev tasks (`just` / `just --list`).
export CGO_ENABLED := "0"

bin := "abc-auth-svc"

# Show recipes (default).
default:
    @just --list

# Fast dev binary at ./abc-auth-svc (no injected version).
build:
    go build -trimpath -o ./{{ bin }} .

# Release-style binary with git-derived version / build time / commit.
build-release out="./abc-auth-svc":
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
    BUILD_TIME="${BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
    GIT_COMMIT="${GIT_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
    mkdir -p "$(dirname "{{ out }}")"
    go build -trimpath \
      -ldflags="-s -w -X 'main.Version=${VERSION}' -X 'main.BuildTime=${BUILD_TIME}' -X 'main.GitCommit=${GIT_COMMIT}'" \
      -o "{{ out }}" .

# Install release-style binary to ~/bin/abc-auth-svc.
install-local:
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
    BUILD_TIME="${BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
    GIT_COMMIT="${GIT_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
    mkdir -p "${HOME}/bin"
    tmp="${HOME}/bin/{{ bin }}.just.tmp.$$"
    go build -trimpath \
      -ldflags="-s -w -X 'main.Version=${VERSION}' -X 'main.BuildTime=${BUILD_TIME}' -X 'main.GitCommit=${GIT_COMMIT}'" \
      -o "${tmp}" .
    mv "${tmp}" "${HOME}/bin/{{ bin }}"
    chmod 0755 "${HOME}/bin/{{ bin }}"
    echo "Installed ${HOME}/bin/{{ bin }}"

# Run locally (dev).
run *args:
    go run . {{ args }}

# Cross-compile helper.
[private]
dist-go goos goarch:
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
    BUILD_TIME="${BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
    GIT_COMMIT="${GIT_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
    mkdir -p dist
    OUT="dist/{{ bin }}-{{ goos }}-{{ goarch }}"
    GOOS="{{ goos }}" GOARCH="{{ goarch }}" go build -trimpath \
      -ldflags="-s -w -X 'main.Version=${VERSION}' -X 'main.BuildTime=${BUILD_TIME}' -X 'main.GitCommit=${GIT_COMMIT}'" \
      -o "${OUT}" .
    echo "Built ${OUT}"

# Service runs on Linux; darwin targets are for local dev only (no windows).
build-linux-amd64: (dist-go "linux" "amd64")
build-linux-arm64: (dist-go "linux" "arm64")
build-darwin-amd64: (dist-go "darwin" "amd64")
build-darwin-arm64: (dist-go "darwin" "arm64")

build-all: build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64

release: build-all
    #!/usr/bin/env bash
    set -euo pipefail
    cd dist && sha256sum \
      {{ bin }}-linux-amd64 \
      {{ bin }}-linux-arm64 \
      {{ bin }}-darwin-amd64 \
      {{ bin }}-darwin-arm64 \
      > sha256sums.txt
    echo "Release artifacts in dist/"

test:
    go test -count=1 ./...

test-unit:
    go test -count=1 -short ./...

vet:
    go vet ./...

fmt:
    gofmt -s -w .

fmt-check:
    test -z "$(gofmt -s -l .)"

tidy:
    go mod tidy

check: vet test

ci: fmt-check check

clean:
    rm -f ./{{ bin }}
    rm -rf dist/
