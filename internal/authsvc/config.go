// Package authsvc is the Go implementation of abc-auth-svc — the seedling-tier
// workbench forward-auth + credential-broker service.
//
// It is a standalone module (mirroring abc-node-probe): a single static binary,
// pure stdlib (net/http + slog), no third-party dependencies. This is Phase 0 —
// the skeleton: redacting slog access logging, /healthz + /readyz, graceful
// shutdown. No upstreams are wired yet.
//
// See brainstorms/abc-workbench/2026-06-04-auth-svc-go-rewrite-plan-v2.md in the
// abc-universe knowledge repo.
package authsvc

import (
	"flag"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// APIVersion is stamped on every response as X-Abc-Auth-API-Version so the CLI
// can negotiate compatibility.
const APIVersion = "v1"

const (
	// DefaultListenAddr keeps the Go service beside the Python one (4181) during
	// the strangler-fig migration.
	DefaultListenAddr = "127.0.0.1:4182"

	defaultReadTimeout   = 10 * time.Second
	defaultWriteTimeout  = 15 * time.Second
	defaultIdleTimeout   = 60 * time.Second
	defaultShutdownGrace = 10 * time.Second
)

// Config is the resolved runtime configuration. Non-secret knobs come from flags
// or env; secrets come from env only (never flags) and are collected into
// ScrubSecrets for the log redactor (populated in Phase 1b when upstream secrets
// are injected — empty in Phase 0).
type Config struct {
	ListenAddr    string
	LogLevel      slog.Level
	MockUpstreams bool
	ShowVersion   bool

	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	IdleTimeout   time.Duration
	ShutdownGrace time.Duration

	ScrubSecrets []string
}

// LoadConfig resolves configuration from args (flags) and getenv (env). getenv is
// injectable for tests. Precedence: flags > env > defaults.
func LoadConfig(args []string, getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}

	cfg := Config{
		ListenAddr:    DefaultListenAddr,
		LogLevel:      L1,
		ReadTimeout:   defaultReadTimeout,
		WriteTimeout:  defaultWriteTimeout,
		IdleTimeout:   defaultIdleTimeout,
		ShutdownGrace: defaultShutdownGrace,
	}

	// Env first, so explicit flags can still override below.
	if v := strings.TrimSpace(getenv("ABC_AUTH_LISTEN")); v != "" {
		cfg.ListenAddr = v
	}
	if v := strings.TrimSpace(getenv("ABC_AUTH_LOG_LEVEL")); v != "" {
		lvl, err := parseLevel(v)
		if err != nil {
			return Config{}, err
		}
		cfg.LogLevel = lvl
	}
	if isTruthy(getenv("ABC_AUTH_MOCK_UPSTREAMS")) {
		cfg.MockUpstreams = true
	}

	fs := flag.NewFlagSet("abc-auth-svc", flag.ContinueOnError)
	listen := fs.String("listen", cfg.ListenAddr, "listen address (host:port)")
	logLevel := fs.String("log-level", levelString(cfg.LogLevel), "log level: info|debug|trace")
	mock := fs.Bool("mock-upstreams", cfg.MockUpstreams, "stub PB/JH/MinIO/Nomad with deterministic responses (local dev)")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	cfg.ListenAddr = *listen
	lvl, err := parseLevel(*logLevel)
	if err != nil {
		return Config{}, err
	}
	cfg.LogLevel = lvl
	cfg.MockUpstreams = *mock
	cfg.ShowVersion = *showVersion

	return cfg, nil
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info", "1", "l1":
		return L1, nil
	case "debug", "2", "l2":
		return L2, nil
	case "trace", "3", "l3":
		return L3, nil
	default:
		return 0, fmt.Errorf("invalid log level %q (want info|debug|trace)", s)
	}
}

func levelString(l slog.Level) string {
	switch {
	case l <= L3:
		return "trace"
	case l <= L2:
		return "debug"
	default:
		return "info"
	}
}

func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
