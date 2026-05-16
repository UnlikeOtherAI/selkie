// Package main is the entry point for the selkie control-plane server.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	redis "github.com/redis/go-redis/v9"

	"github.com/unlikeotherai/selkie/internal/admin"
	"github.com/unlikeotherai/selkie/internal/audit"
	"github.com/unlikeotherai/selkie/internal/auth"
	"github.com/unlikeotherai/selkie/internal/config"
	"github.com/unlikeotherai/selkie/internal/devices"
	"github.com/unlikeotherai/selkie/internal/mobile"
	"github.com/unlikeotherai/selkie/internal/nat"
	"github.com/unlikeotherai/selkie/internal/overlay"
	"github.com/unlikeotherai/selkie/internal/policy"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
	"github.com/unlikeotherai/selkie/internal/services"
	"github.com/unlikeotherai/selkie/internal/sessions"
	"github.com/unlikeotherai/selkie/internal/store"
	"github.com/unlikeotherai/selkie/internal/telemetry"
	"github.com/unlikeotherai/selkie/internal/wg"
)

// shutdownGrace bounds the graceful shutdown window. After this many seconds,
// the second SIGTERM accelerator cancels the shutdown context to force-quit
// in-flight connections.
const shutdownGrace = 30 * time.Second

// errPrematureServerClose signals that srv.Serve returned http.ErrServerClosed
// (mapped to nil on errCh by the serve goroutine) before sigCtx fired. The
// only way to observe ErrServerClosed is via srv.Shutdown or srv.Close — if
// neither was triggered by our shutdown path, something external closed the
// server and we must not exit silently.
var errPrematureServerClose = errors.New("http server closed before shutdown signal")

func main() {
	cfg := config.Load()
	logger := buildLogger(cfg.LogLevel)
	defer logger.Sync() //nolint:errcheck // best-effort flush on exit

	if err := cfg.Validate(); err != nil {
		logger.Fatal("invalid configuration", zap.Error(err))
	}
	if cfg.InternalSessionSecret == "" && cfg.DevMode {
		logger.Warn("INTERNAL_SESSION_SECRET is empty; DEV_MODE is enabled, continuing with empty HMAC key — do NOT use this configuration in production")
	}
	for _, w := range cfg.Warnings {
		logger.Warn("config warning", zap.String("warning", w))
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Second-signal accelerator: signal.NotifyContext only cancels sigCtx
	// once, so a second Ctrl-C or SIGTERM during the 30s shutdown drain
	// would otherwise be a no-op. forceShutdown is closed on the second
	// signal so runServe can cancel its shutdown context and force-quit.
	//
	// signal.Notify must be registered AFTER sigCtx fires. Go delivers
	// signals to every registered channel, so registering ch up front
	// would cause the FIRST SIGTERM to be buffered into ch as well,
	// collapsing the second-signal escalator into immediate force-quit
	// on the first signal.
	forceShutdown := make(chan struct{})
	go func() {
		<-sigCtx.Done()
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(ch)
		select {
		case <-ch:
			close(forceShutdown)
		case <-time.After(2 * shutdownGrace):
			// Process has exited cleanly via normal drain; never fired.
		}
	}()

	if err := runServe(sigCtx, forceShutdown, cfg, logger); err != nil {
		logger.Fatal("server exited with error", zap.Error(err))
	}
}

func runServe(sigCtx context.Context, forceShutdown <-chan struct{}, cfg config.Config, logger *zap.Logger) error {
	// Thread sigCtx into every long-lived init call so SIGTERM during boot
	// (slow migrations, wireguard hub setup) unblocks the boot path rather
	// than waiting for k8s SIGKILL. A separate detached context is used
	// only for shutdown-time cleanup (telemetry flush) where cancellation
	// from the now-cancelled sigCtx would defeat the flush.
	ctx := sigCtx

	otelShutdown, err := telemetry.Init(ctx, telemetry.Config{
		Endpoint:       cfg.OTELExporterOTLPEndpoint,
		ServiceName:    "selkie-server",
		ServiceVersion: "0.1.0",
	}, logger)
	if err != nil {
		return fmt.Errorf("init telemetry: %w", err)
	}
	defer func() {
		// Use a detached context so a cancelled sigCtx does not abort
		// the otel exporter flush.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = otelShutdown(shutdownCtx)
	}()

	db, err := store.OpenDB(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()
	if migErr := db.RunMigrations(ctx, "migrations"); migErr != nil {
		return fmt.Errorf("run migrations: %w", migErr)
	}
	logger.Info("migrations applied")

	rdb, err := store.NewRedis(ctx, cfg)
	if err != nil {
		return fmt.Errorf("open redis: %w", err)
	}
	if rdb != nil {
		defer rdb.Close()
		logger.Info("redis connected")
	} else {
		logger.Warn("redis disabled (REDIS_URL not set), SSE fan-out unavailable")
	}

	// Validate() guarantees rdb is non-nil in non-dev mode. In dev mode we
	// fall back to a process-local in-memory limiter so rate-limited
	// endpoints stay testable without Redis. The in-memory limiter is not
	// safe across replicas; production paths always use RedisLimiter.
	var limiter ratelimit.Limiter
	if rdb != nil {
		limiter = ratelimit.NewRedisLimiter(rdb.Client)
	} else if cfg.DevMode {
		limiter = ratelimit.NewMemoryLimiter()
		logger.Warn("DEV_MODE: using in-memory rate limiter (not safe across replicas)")
	}

	var overlayAlloc *overlay.Allocator
	if cfg.WGOverlayCIDR != "" {
		overlayAlloc, err = overlay.New(db.Pool, cfg.WGOverlayCIDR)
		if err != nil {
			return fmt.Errorf("init overlay allocator: %w", err)
		}
	}

	var hub *wg.Hub
	hub, err = wg.NewHub(db, cfg, logger)
	if err != nil {
		return fmt.Errorf("init wireguard hub: %w", err)
	}
	if hub != nil {
		if err := hub.Init(ctx, cfg.WGServerPort); err != nil {
			return fmt.Errorf("init wireguard hub: %w", err)
		}
		logger.Info("wireguard hub initialized", zap.String("interface", cfg.WGInterfaceName))
	}

	// Policy engine (allow-all when OPA_ENDPOINT is empty).
	policyEngine := policy.New(cfg.OPAEndpoint, logger)

	// Statsdb subscriber. Defer order is LIFO, so registration sequence
	// matters: we want unwind order statsWG.Wait → statsClient.Close →
	// rdb.Close → db.Close. The subscriber holds the Redis client *and*
	// an acquired pgx connection mid-Exec; if statsClient or the db pool
	// is closed before the goroutine returns, Exec races against a
	// torn-down dependency.
	//
	// Registration order below: statsClient.Close FIRST, then statsWG.Wait
	// SECOND. LIFO then runs Wait first (subscriber exits), then closes
	// the redis client, and only after that does the outer rdb.Close /
	// db.Close defer chain run.
	if cfg.CoturnRedisStatsDB != "" {
		statsOpts, err := redis.ParseURL(cfg.CoturnRedisStatsDB)
		if err != nil {
			return fmt.Errorf("parse coturn redis statsdb url: %w", err)
		}
		statsClient := redis.NewClient(statsOpts)
		defer statsClient.Close()
		var statsWG sync.WaitGroup
		defer statsWG.Wait()
		statsSub := nat.NewStatsSubscriber(statsClient, db, logger)
		statsWG.Add(1)
		go func() {
			defer statsWG.Done()
			statsSub.Run(sigCtx)
		}()
		logger.Info("coturn statsdb subscriber started")
	}

	// ready is initialized to false and only flipped to true after the
	// listener has successfully bound. A stuck listener (port-in-use, perm
	// error) must not be reported as ready to k8s/LB probes.
	ready := &atomic.Bool{}

	r := chi.NewRouter()

	// OTel HTTP middleware (noop when endpoint is empty).
	r.Use(telemetry.Middleware(cfg.OTELExporterOTLPEndpoint))

	// /healthz is a liveness probe: it stays 200 while the process is alive,
	// including during the 30s shutdown drain. Use /readyz for drain-aware
	// routing — k8s should treat the two distinctly.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	r.Get("/readyz", func(w http.ResponseWriter, req *http.Request) {
		if !ready.Load() {
			http.Error(w, "shutting down", http.StatusServiceUnavailable)
			return
		}
		pCtx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
		defer cancel()
		if pingErr := db.Ping(pCtx); pingErr != nil {
			http.Error(w, "db unavailable", http.StatusServiceUnavailable)
			return
		}
		if rdb != nil {
			if pingErr := rdb.Ping(pCtx); pingErr != nil {
				http.Error(w, "redis unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready"))
	})

	auditor := audit.New(db, logger)

	auth.NewCallbackHandler(db, cfg, auditor, logger, limiter).Mount(r)
	admin.New(db, logger, cfg, auditor, limiter).Mount(r)
	devices.New(db, logger, cfg, overlayAlloc, auditor, hub, limiter).Mount(r)
	mobile.New(db, logger, cfg, overlayAlloc, auditor, hub, limiter).Mount(r)
	services.New(db, logger, cfg, auditor, limiter).Mount(r)
	sessions.New(db, rdb, logger, cfg, policyEngine, limiter, auditor).Mount(r)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.ServerPort),
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		// Bound request headers to 16KiB. Default is 1MiB, which lets a
		// crafted User-Agent bloat audit_events rows at attacker-chosen
		// scale (see internal/auth.middleware reject-audit truncation).
		MaxHeaderBytes: 16 << 10,
	}

	// Bind the listener synchronously so a bind failure surfaces as a boot
	// error rather than a goroutine error after ready has been flipped.
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	// Resolve the actually-bound port BEFORE flipping ready — when
	// ServerPort=0 the kernel assigns an ephemeral port and tests/operators
	// need that real value, not the literal 0 from cfg.
	boundPort := cfg.ServerPort
	if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
		boundPort = tcpAddr.Port
	}
	ready.Store(true)
	logger.Info("listening", zap.Int("port", boundPort))

	// serveErr distinguishes "clean shutdown initiated by SIGTERM" (nil)
	// from "Serve returned spontaneously before shutdown" (errSilentServeExit).
	// http.ErrServerClosed only occurs after srv.Shutdown, so seeing it on
	// the goroutine path before sigCtx fires would mean a third party
	// called srv.Close — that is a defect worth surfacing.
	errCh := make(chan error, 1)
	go func() {
		serveErr := srv.Serve(ln)
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
			return
		}
		errCh <- nil
	}()

	select {
	case serveErr := <-errCh:
		if serveErr == nil {
			return errPrematureServerClose
		}
		return serveErr
	case <-sigCtx.Done():
	}

	ready.Store(false)
	logger.Info("shutting down")

	shutCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	// A second SIGTERM during the drain force-closes in-flight connections.
	// http.Server.Shutdown returns when the shutdown context is cancelled
	// but does NOT actually close hijacked or long-running connections —
	// only srv.Close() does. So we cancel() to unblock Shutdown AND call
	// srv.Close() to terminate sockets that ignore graceful drain.
	go func() {
		select {
		case <-forceShutdown:
			logger.Warn("second shutdown signal received, forcing close of in-flight connections")
			cancel()
			_ = srv.Close()
		case <-shutCtx.Done():
		}
	}()
	if err := srv.Shutdown(shutCtx); err != nil { //nolint:contextcheck // intentionally new context for graceful shutdown
		return err
	}
	return <-errCh
}

func buildLogger(level string) *zap.Logger {
	cfg := zap.NewProductionConfig()
	if parsed, err := zapcore.ParseLevel(level); err == nil {
		cfg.Level = zap.NewAtomicLevelAt(parsed)
	}
	l, err := cfg.Build()
	if err != nil {
		l, _ = zap.NewProduction() //nolint:errcheck // fallback logger, can't fail in practice
	}
	return l
}
