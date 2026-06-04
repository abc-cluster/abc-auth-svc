package authsvc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
)

// Server is the abc-auth-svc HTTP server.
type Server struct {
	cfg   Config
	log   *slog.Logger
	build BuildInfo
	up    Upstreams
	http  *http.Server
}

// NewServer builds the server with its middleware chain and routes.
//
// Middleware order (outer → inner): withBaseLogger → VersionHeader → RequestID →
// AccessLog → Recoverer → mux. Recoverer is inside AccessLog so a recovered
// panic's 500 is reflected in the access record.
func NewServer(cfg Config, logger *slog.Logger, build BuildInfo, up Upstreams) *Server {
	s := &Server{cfg: cfg, log: logger, build: build, up: up}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("GET /version", s.handleVersion)
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

// Run starts the server and blocks until ctx is cancelled, then gracefully shuts
// down within the configured grace window.
func (s *Server) Run(ctx context.Context) error {
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
