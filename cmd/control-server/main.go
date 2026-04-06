// Package main is the entry point for the selkie control-plane server.
package main

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/unlikeotherai/selkie/internal/nat"
	"github.com/unlikeotherai/selkie/internal/overlay"
	"github.com/unlikeotherai/selkie/internal/policy"
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

	ctx := context.Background()
	if err := runServe(ctx, cfg, logger); err != nil {
		logger.Fatal("server exited with error", zap.Error(err))
	}
}

func runServe(ctx context.Context, cfg config.Config, logger *zap.Logger) error {
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

	// Coturn redis-statsdb subscriber for relay allocation tracking.
	if cfg.CoturnRedisStatsDB != "" {
		statsOpts, err := redis.ParseURL(cfg.CoturnRedisStatsDB)
		if err != nil {
			return fmt.Errorf("parse coturn redis statsdb url: %w", err)
		}
		statsClient := redis.NewClient(statsOpts)
		defer statsClient.Close()
		statsSub := nat.NewStatsSubscriber(statsClient, db, logger)
		go statsSub.Run(ctx)
		logger.Info("coturn statsdb subscriber started")
	}

	ready := &atomic.Bool{}
	ready.Store(true)

	r := chi.NewRouter()

	// OTel HTTP middleware (noop when endpoint is empty).
	r.Use(telemetry.Middleware(cfg.OTELExporterOTLPEndpoint))

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

	auth.NewCallbackHandler(db, cfg, auditor, logger).Mount(r)
	admin.New(db, logger, cfg).Mount(r)
	devices.New(db, logger, cfg, overlayAlloc, auditor, hub).Mount(r)
	services.New(db, logger, cfg).Mount(r)
	sessions.New(db, rdb, logger, cfg, policyEngine).Mount(r)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.ServerPort),
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", zap.Int("port", cfg.ServerPort))
		if listenErr := srv.ListenAndServe(); listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
			errCh <- listenErr
		}
		close(errCh)
	}()

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
