package httpx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/encorebom/encorebom/libs/go-shared/platform/obs"
)

// ServerConfig configures Run.
type ServerConfig struct {
	Addr          string
	MetricsAddr   string
	Handler       http.Handler
	Metrics       *obs.Metrics
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	IdleTimeout   time.Duration
	ShutdownGrace time.Duration
}

// Run starts the application and metrics listeners and blocks until SIGINT or
// SIGTERM, then shuts down gracefully.
//
// Graceful shutdown is not a nicety here. A worker killed mid-job leaves a
// JetStream message unacked, which is safe because jobs are idempotent — but a
// gateway killed mid-request returns a connection reset the client cannot
// distinguish from a real failure. Draining costs a few seconds and removes a
// whole class of confusing error report.
func Run(ctx context.Context, cfg ServerConfig) error {
	if cfg.ShutdownGrace == 0 {
		cfg.ShutdownGrace = 20 * time.Second
	}

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           cfg.Handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	errCh := make(chan error, 2)

	go func() {
		slog.Info("http listener started", "addr", cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http listener: %w", err)
		}
	}()

	// Metrics listen on a separate port so an ingress that exposes the app port
	// does not accidentally expose /metrics to the internet.
	var metricsSrv *http.Server
	if cfg.Metrics != nil && cfg.MetricsAddr != "" {
		metricsSrv = obs.ServeMetrics(cfg.MetricsAddr, cfg.Metrics)
		go func() {
			slog.Info("metrics listener started", "addr", cfg.MetricsAddr)
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("metrics listener: %w", err)
			}
		}()
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("shutdown signal received", "grace", cfg.ShutdownGrace.String())
	}

	// A fresh context: the parent is already cancelled by the signal, so
	// deriving from it would abort the drain immediately.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()

	if metricsSrv != nil {
		_ = metricsSrv.Shutdown(shutdownCtx)
	}
	if err := srv.Shutdown(shutdownCtx); err != nil {
		// Grace expired with requests still in flight. Force the close so the
		// process exits rather than hanging a rolling deploy.
		slog.Error("graceful shutdown timed out, forcing close", "cause", err.Error())
		_ = srv.Close()
		return fmt.Errorf("shutdown: %w", err)
	}

	slog.Info("shutdown complete")
	return nil
}
