// Command abc-auth-svc is the Go implementation of the seedling-tier workbench
// forward-auth + credential-broker service.
//
// It is a standalone, dependency-free Go module (mirroring abc-node-probe): a
// single static binary built with the same justfile / CI / ldflags conventions.
//
// Phase 0 (skeleton): stdlib net/http server with redacting slog access logging,
// /healthz + /readyz + /version, graceful shutdown. Runs on 127.0.0.1:4182 by
// default, beside the Python service on 4181, during the strangler-fig migration.
//
//	abc-auth-svc -listen 127.0.0.1:4182 -log-level info
//	ABC_AUTH_LISTEN=127.0.0.1:4182 abc-auth-svc
//	abc-auth-svc -version
//
// See brainstorms/abc-workbench/2026-06-04-auth-svc-go-rewrite-plan-v2.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/abc-cluster/abc-auth-svc/internal/authsvc"
)

// Version, BuildTime, and GitCommit are injected at build time via ldflags.
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	if err := run(); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "abc-auth-svc: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := authsvc.LoadConfig(os.Args[1:], os.Getenv)
	if err != nil {
		return err
	}

	build := authsvc.BuildInfo{Version: Version, BuildTime: BuildTime, GitCommit: GitCommit}

	if cfg.ShowVersion {
		fmt.Printf("abc-auth-svc %s (commit %s, built %s)\n", build.Version, build.GitCommit, build.BuildTime)
		return nil
	}

	logger := authsvc.NewLogger(os.Stderr, cfg.LogLevel, cfg.ScrubSecrets)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	up := authsvc.BuildUpstreams(cfg)
	return authsvc.NewServer(cfg, logger, build, up).Run(ctx)
}
