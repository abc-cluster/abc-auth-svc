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

	// Upstream defaults (overridable by flag/env).
	DefaultNomadAddr        = "http://127.0.0.1:4646"
	DefaultJupyterHubAPIURL = "http://127.0.0.1:15001/hub/api"
	DefaultHubPublicURL     = "https://workbench.seedling.abc-cluster.cloud"

	// PocketBase + cluster defaults (env-driven in production; Nomad injects them).
	DefaultPocketBaseURL        = "http://127.0.0.1:8091"
	DefaultPBAdminEmail         = "abc-auth@internal"
	DefaultClusterNomadEndpoint = "https://nomad.seedling.abc-cluster.cloud"
	DefaultClusterMinioEndpoint = "https://s3.seedling.abc-cluster.cloud"
	DefaultClusterDatacenter    = "seedling-prod"
	DefaultClusterHeadPool      = "platform"
	DefaultClusterWorkerPool    = "compute"

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

	// Upstream endpoints (Phase 1+). JupyterHubAdminToken and PBAdminPassword are
	// secrets — env only, never flags — and are added to ScrubSecrets so they can
	// never appear in logs.
	NomadAddr            string
	JupyterHubAPIURL     string
	JupyterHubAdminToken string
	HubPublicURL         string

	// PocketBase (slot store) + cluster identity for the credential bundle.
	PocketBaseURL        string
	PBAdminEmail         string
	PBAdminPassword      string
	ClusterNomadEndpoint string
	ClusterMinioEndpoint string
	ClusterDatacenter    string
	ClusterHeadPool      string
	ClusterWorkerPool    string

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
		ListenAddr:       DefaultListenAddr,
		LogLevel:         L1,
		NomadAddr:        DefaultNomadAddr,
		JupyterHubAPIURL: DefaultJupyterHubAPIURL,
		HubPublicURL:     DefaultHubPublicURL,
		ReadTimeout:      defaultReadTimeout,
		WriteTimeout:     defaultWriteTimeout,
		IdleTimeout:      defaultIdleTimeout,
		ShutdownGrace:    defaultShutdownGrace,
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
	if v := strings.TrimSpace(getenv("NOMAD_ADDR")); v != "" {
		cfg.NomadAddr = v
	}
	if v := strings.TrimSpace(getenv("JUPYTERHUB_API_URL")); v != "" {
		cfg.JupyterHubAPIURL = v
	}
	if v := strings.TrimSpace(getenv("HUB_PUBLIC_URL")); v != "" {
		cfg.HubPublicURL = v
	}
	cfg.JupyterHubAdminToken = strings.TrimSpace(getenv("JUPYTERHUB_API_TOKEN")) // secret: env only

	// PocketBase + cluster config — env with defaults (no flags; Nomad injects).
	cfg.PocketBaseURL = getenvOr(getenv, "POCKETBASE_URL", DefaultPocketBaseURL)
	cfg.PBAdminEmail = getenvOr(getenv, "PB_ADMIN_EMAIL", DefaultPBAdminEmail)
	cfg.PBAdminPassword = strings.TrimSpace(getenv("PB_ADMIN_PASSWORD")) // secret: env only
	cfg.ClusterNomadEndpoint = getenvOr(getenv, "CLUSTER_NOMAD_ENDPOINT", DefaultClusterNomadEndpoint)
	cfg.ClusterMinioEndpoint = getenvOr(getenv, "CLUSTER_MINIO_ENDPOINT", DefaultClusterMinioEndpoint)
	cfg.ClusterDatacenter = getenvOr(getenv, "CLUSTER_DATACENTER", DefaultClusterDatacenter)
	cfg.ClusterHeadPool = getenvOr(getenv, "CLUSTER_HEAD_POOL", DefaultClusterHeadPool)
	cfg.ClusterWorkerPool = getenvOr(getenv, "CLUSTER_WORKER_POOL", DefaultClusterWorkerPool)

	fs := flag.NewFlagSet("abc-auth-svc", flag.ContinueOnError)
	listen := fs.String("listen", cfg.ListenAddr, "listen address (host:port)")
	logLevel := fs.String("log-level", levelString(cfg.LogLevel), "log level: info|debug|trace")
	mock := fs.Bool("mock-upstreams", cfg.MockUpstreams, "stub PB/JH/MinIO/Nomad with deterministic responses (local dev)")
	showVersion := fs.Bool("version", false, "print version and exit")
	nomadAddr := fs.String("nomad-addr", cfg.NomadAddr, "Nomad API address for token validation")
	jhAPIURL := fs.String("jupyterhub-api-url", cfg.JupyterHubAPIURL, "JupyterHub API base URL")
	hubPublicURL := fs.String("hub-public-url", cfg.HubPublicURL, "public workbench URL returned to clients")
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
	cfg.NomadAddr = *nomadAddr
	cfg.JupyterHubAPIURL = *jhAPIURL
	cfg.HubPublicURL = *hubPublicURL

	// Secrets feed the exact-value log scrub.
	for _, sec := range []string{cfg.JupyterHubAdminToken, cfg.PBAdminPassword} {
		if sec != "" {
			cfg.ScrubSecrets = append(cfg.ScrubSecrets, sec)
		}
	}

	return cfg, nil
}

func getenvOr(getenv func(string) string, key, def string) string {
	if v := strings.TrimSpace(getenv(key)); v != "" {
		return v
	}
	return def
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
