package authsvc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Server is the abc-auth-svc HTTP server.
type Server struct {
	cfg          Config
	log          *slog.Logger
	build        BuildInfo
	up           Upstreams
	session      sessionVerifier
	codes        *magicCodeStore
	levelVar     *slog.LevelVar // runtime log-level control; nil = fixed level
	shadowURL    string
	shadowClient *http.Client
	http         *http.Server
}

// SetLevelVar wires the logger's runtime-mutable level into the server so
// POST /manage/log-level can change it without a restart. Called once by
// main.go after NewLeveledLogger. When nil (tests), the log-level endpoint
// reports the static level and refuses to change it.
func (s *Server) SetLevelVar(lv *slog.LevelVar) { s.levelVar = lv }

// NewServer builds the server with its middleware chain and routes.
//
// Middleware order (outer → inner): withBaseLogger → VersionHeader → RequestID →
// AccessLog → Recoverer → mux. Recoverer is inside AccessLog so a recovered
// panic's 500 is reflected in the access record.
func NewServer(cfg Config, logger *slog.Logger, build BuildInfo, up Upstreams) *Server {
	s := &Server{
		cfg: cfg, log: logger, build: build, up: up,
		session:   sessionVerifier{secret: []byte(cfg.SessionSecret)},
		codes:     newMagicCodeStore(),
		shadowURL: cfg.ShadowValidateURL,
		shadowClient: &http.Client{
			Timeout: 3 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse // don't follow the 302 — it's the signal
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("GET /version", s.handleVersion)
	// Forward-auth hot path.
	mux.HandleFunc("GET /validate", s.handleValidate)
	mux.HandleFunc("GET /validate-optional", s.handleValidateOptional)
	mux.HandleFunc("GET /validate-shadow", s.handleValidateShadow)
	// Auth flows (browser + CLI).
	mux.HandleFunc("GET /auth/login", s.handleLoginGet)
	mux.HandleFunc("POST /auth/login", s.handleLoginPost)
	mux.HandleFunc("GET /auth/logout", s.handleLogout)
	mux.HandleFunc("GET /auth/me", s.handleAuthMe)
	// Caddy serves abc-auth-svc under /auth/* and strips the prefix, so the
	// Python service sees /workbench/token. Register both so the Go service works
	// whether or not the per-path Caddy rule strips /auth.
	mux.HandleFunc("POST /workbench/token", s.handleWorkbenchToken)
	mux.HandleFunc("POST /auth/workbench/token", s.handleWorkbenchToken)
	// Opaque-token credential broker (cred_source = seedling/v1). Caddy strips
	// /auth, so register both.
	mux.HandleFunc("POST /auth/exchange", s.handleAuthExchange)
	mux.HandleFunc("POST /exchange", s.handleAuthExchange)
	// Config refresh (`abc auth config refresh`) and operator cred-source flip.
	mux.HandleFunc("GET /slots/me/config", s.handleSlotsMeConfig)
	mux.HandleFunc("GET /auth/slots/me/config", s.handleSlotsMeConfig)
	mux.HandleFunc("POST /manage/slots/{slot}/cred-source", s.handleCredSource)
	mux.HandleFunc("POST /auth/manage/slots/{slot}/cred-source", s.handleCredSource)
	mux.HandleFunc("GET /manage/slots/{slot}/diag", s.handleSlotDiag)
	mux.HandleFunc("GET /auth/manage/slots/{slot}/diag", s.handleSlotDiag)
	// Magic-link pair (`abc portal open *`).
	mux.HandleFunc("POST /auth/cli-token", s.handleCLITokenPost)
	mux.HandleFunc("POST /cli-token", s.handleCLITokenPost)
	mux.HandleFunc("GET /auth/redeem", s.handleAuthRedeem)
	mux.HandleFunc("GET /redeem", s.handleAuthRedeem)
	// MinIO console SSO (used by `abc portal open minio`).
	mux.HandleFunc("GET /auth/minio-login", s.handleAuthMinIOLogin)
	mux.HandleFunc("GET /minio-login", s.handleAuthMinIOLogin)
	// External-integrator Nomad token introspection.
	mux.HandleFunc("GET /verify", s.handleVerifyNomad)
	mux.HandleFunc("POST /verify", s.handleVerifyNomad)
	mux.HandleFunc("GET /verify-namespace", s.handleVerifyNomad)
	mux.HandleFunc("POST /verify-namespace", s.handleVerifyNomad)
	// Operator list / single-slot GET.
	mux.HandleFunc("GET /manage/slots", s.handleManageListSlots)
	mux.HandleFunc("GET /auth/manage/slots", s.handleManageListSlots)
	mux.HandleFunc("GET /manage/slots/{slot}", s.handleManageGetSlot)
	mux.HandleFunc("GET /auth/manage/slots/{slot}", s.handleManageGetSlot)
	// /healthz alias for Python compatibility.
	mux.HandleFunc("GET /auth/health", s.handleHealthz)
	// Phase 4 — fully Go-served as of cutover finalisation.
	mux.HandleFunc("POST /auth/secrets/put", s.handleSecretsPut)
	mux.HandleFunc("POST /secrets/put", s.handleSecretsPut)
	mux.HandleFunc("POST /auth/secrets/get", s.handleSecretsGet)
	mux.HandleFunc("POST /secrets/get", s.handleSecretsGet)
	mux.HandleFunc("POST /slots/claim", s.handleSlotsClaim)
	mux.HandleFunc("POST /auth/slots/claim", s.handleSlotsClaim)
	mux.HandleFunc("POST /manage/slots/{slot}/suspend", s.handleManageSuspend)
	mux.HandleFunc("POST /auth/manage/slots/{slot}/suspend", s.handleManageSuspend)
	mux.HandleFunc("POST /manage/slots/{slot}/reactivate", s.handleManageReactivate)
	mux.HandleFunc("POST /auth/manage/slots/{slot}/reactivate", s.handleManageReactivate)
	mux.HandleFunc("POST /manage/slots/{slot}/rotate", s.handleManageRotate)
	mux.HandleFunc("POST /auth/manage/slots/{slot}/rotate", s.handleManageRotate)
	// Runtime log-level control (operator-gated) — flip to debug/trace to
	// capture an issue live, then flip back, without restarting the service.
	mux.HandleFunc("GET /manage/log-level", s.handleLogLevel)
	mux.HandleFunc("POST /manage/log-level", s.handleLogLevel)
	mux.HandleFunc("GET /auth/manage/log-level", s.handleLogLevel)
	mux.HandleFunc("POST /auth/manage/log-level", s.handleLogLevel)
	mux.HandleFunc("/", s.handleNotFound)

	handler := chain(mux,
		withBaseLogger(logger),
		VersionHeader,
		RequestID,
		AccessLog,
		Recoverer,
	)

	s.http = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      handler,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}
	return s
}

// Handler returns the fully-wrapped HTTP handler (used in tests).
func (s *Server) Handler() http.Handler { return s.http.Handler }

// Addr returns the configured listen address.
func (s *Server) Addr() string { return s.http.Addr }

// logStartupBanner emits a structured summary of upstream config (URLs +
// token shapes + reachability) at L1 on startup. Mirrors the Python
// service's banner (lines 2557+) so both drift surfaces from the
// project_authsvc_deploy_drift memory (placeholder admin token, Hub URL
// mismatch) self-announce on every alloc restart.
func (s *Server) logStartupBanner(ctx context.Context) {
	// Token shape — never log the secret, only its length + 8-char prefix +
	// placeholder/unset flags. Same approach as the Python service.
	jhTok := s.cfg.JupyterHubAdminToken
	jhTokState, jhTokPrefix := tokenShape(jhTok)

	s.log.LogAttrs(ctx, L1, "server.startup.config",
		slog.String("listen", s.cfg.ListenAddr),
		slog.String("jupyterhub_api_url", s.cfg.JupyterHubAPIURL),
		slog.String("jupyterhub_admin_token", jhTokState),
		slog.String("jupyterhub_admin_token_prefix", jhTokPrefix),
		slog.Int("jupyterhub_admin_token_len", len(jhTok)),
		slog.String("nomad_addr", s.cfg.NomadAddr),
		slog.String("pocketbase_url", s.cfg.PocketBaseURL),
		slog.String("minio_console_url", s.cfg.MinioConsoleURL),
	)

	// Quick reachability probe for JH — distinguishes "Hub down/wrong URL"
	// from "Hub up but admin token rejected". Fails open: never blocks
	// startup.
	if ex, ok := s.up.Hub.(HubUserExister); ok {
		ctxProbe, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		// Probe with a sentinel user that won't exist — JH still answers
		// 200 (with auth) or 404 (auth OK, user not found); both indicate
		// the Hub is up and our admin token works. A non-2xx/4xx (e.g.
		// transport error) indicates Hub unreachable.
		if _, probeErr := ex.UserExists(ctxProbe, "__diag_probe__"); probeErr != nil {
			s.log.LogAttrs(ctx, L1, "server.startup.jupyterhub_probe",
				slog.String("status", "unreachable_or_unauthorized"),
				slog.String("error", probeErr.Error()))
		} else {
			s.log.LogAttrs(ctx, L1, "server.startup.jupyterhub_probe",
				slog.String("status", "reachable"))
		}
	}
}

// tokenShape returns a (state, prefix) pair for non-secret logging.
//   - "unset" / "(empty)" — token blank
//   - "placeholder" / "REPLACE_…"  — install script never substituted it
//   - "set" / first 8 chars         — looks real
func tokenShape(tok string) (state, prefix string) {
	switch {
	case tok == "":
		return "unset", "(empty)"
	case strings.Contains(tok, "REPLACE_WITH"):
		return "placeholder", tok
	default:
		if len(tok) >= 8 {
			return "set", tok[:8]
		}
		return "set", tok
	}
}

// Run starts the server and blocks until ctx is cancelled, then gracefully shuts
// down within the configured grace window.
func (s *Server) Run(ctx context.Context) error {
	s.logStartupBanner(ctx)
	errCh := make(chan error, 1)
	go func() {
		s.log.LogAttrs(ctx, L1, "server.listening",
			slog.String("addr", s.cfg.ListenAddr),
			slog.String("version", s.build.Version),
			slog.String("commit", s.build.GitCommit),
		)
		if err := s.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		s.log.LogAttrs(context.Background(), L1, "server.shutting_down")
		shutCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownGrace)
		defer cancel()
		return s.http.Shutdown(shutCtx)
	}
}
