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

	"github.com/unlikeotherai/silkie/internal/config"
	"github.com/unlikeotherai/silkie/internal/admin"
	"github.com/unlikeotherai/silkie/internal/auth"
	"github.com/unlikeotherai/silkie/internal/devices"
	"github.com/unlikeotherai/silkie/internal/overlay"
	"github.com/unlikeotherai/silkie/internal/sessions"
	"github.com/unlikeotherai/silkie/internal/store"
)

func main() {
	cfg := config.Load()
	logger := buildLogger(cfg.LogLevel)
	defer logger.Sync() //nolint:errcheck

	ctx := context.Background()
	if err := runServe(ctx, cfg, logger); err != nil {
		logger.Fatal("server exited with error", zap.Error(err))
	}
}

func runServe(ctx context.Context, cfg config.Config, logger *zap.Logger) error {
	db, err := store.OpenDB(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()
	if err := db.RunMigrations(ctx, "migrations"); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}
	logger.Info("migrations applied")

	rdb, err := store.NewRedis(ctx, cfg)
	if err != nil {
		return fmt.Errorf("open redis: %w", err)
	}
	defer rdb.Close() //nolint:errcheck

	var overlayAlloc *overlay.Allocator
	if cfg.WGOverlayCIDR != "" {
		overlayAlloc, err = overlay.New(db.Pool, cfg.WGOverlayCIDR)
		if err != nil {
			return fmt.Errorf("init overlay allocator: %w", err)
		}
	}

	ready := &atomic.Bool{}
	ready.Store(true)

	r := chi.NewRouter()

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok")) //nolint:errcheck
	})
	r.Get("/readyz", func(w http.ResponseWriter, req *http.Request) {
		if !ready.Load() {
			http.Error(w, "shutting down", http.StatusServiceUnavailable)
			return
		}
		pCtx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
		defer cancel()
		if err := db.Ping(pCtx); err != nil {
			http.Error(w, "db unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := rdb.Ping(pCtx); err != nil {
			http.Error(w, "redis unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready")) //nolint:errcheck
	})

	auth.NewCallbackHandler(db, cfg).Mount(r)
	admin.New().Mount(r)
	devices.New(db, logger, cfg, overlayAlloc).Mount(r)
	sessions.New(db, rdb, logger, cfg).Mount(r)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.ServerPort),
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", zap.Int("port", cfg.ServerPort))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
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
	if err := srv.Shutdown(shutCtx); err != nil {
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
		l, _ = zap.NewProduction()
	}
	return l
}
