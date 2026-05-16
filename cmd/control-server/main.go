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

	if err := runServe(sigCtx, cfg, logger); err != nil {
		logger.Fatal("server exited with error", zap.Error(err))
	}
}

func runServe(sigCtx context.Context, cfg config.Config, logger *zap.Logger) error {
	ctx := context.Background()
	// Initialize OpenTelemetry (noop when endpoint is empty).
	otelShutdown, err := telemetry.Init(ctx, telemetry.Config{
		Endpoint:       cfg.OTELExporterOTLPEndpoint,
		ServiceName:    "selkie-server",
		ServiceVersion: "0.1.0",
	}, logger)
	if err != nil {
		return fmt.Errorf("init telemetry: %w", err)
	}
	defer otelShutdown(ctx) //nolint:errcheck // best-effort flush on exit

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

	// Coturn redis-statsdb subscriber for relay allocation tracking. Bound
	// to sigCtx so SIGTERM unblocks the subscriber loop and stops in-flight
	// Pool.Exec calls before db.Close runs in deferred order.
	if cfg.CoturnRedisStatsDB != "" {
		statsOpts, err := redis.ParseURL(cfg.CoturnRedisStatsDB)
		if err != nil {
			return fmt.Errorf("parse coturn redis statsdb url: %w", err)
		}
		statsClient := redis.NewClient(statsOpts)
		defer statsClient.Close()
		statsSub := nat.NewStatsSubscriber(statsClient, db, logger)
		go statsSub.Run(sigCtx)
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
	admin.New(db, logger, cfg, auditor).Mount(r)
	devices.New(db, logger, cfg, overlayAlloc, auditor, hub, limiter).Mount(r)
	mobile.New(db, logger, cfg, overlayAlloc, auditor, hub, limiter).Mount(r)
	services.New(db, logger, cfg, auditor).Mount(r)
	sessions.New(db, rdb, logger, cfg, policyEngine, limiter, auditor).Mount(r)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.ServerPort),
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Bind the listener synchronously so a bind failure surfaces as a boot
	// error rather than a goroutine error after ready has been flipped.
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	ready.Store(true)
	logger.Info("listening", zap.Int("port", cfg.ServerPort))

	errCh := make(chan error, 1)
	go func() {
		if serveErr := srv.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-sigCtx.Done():
	}

	ready.Store(false)
	logger.Info("shutting down")

	shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
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
