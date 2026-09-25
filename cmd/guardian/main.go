package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/1day0fmylife/Guardian/internal/config"
	"github.com/1day0fmylife/Guardian/internal/httpapi"
	"github.com/1day0fmylife/Guardian/internal/store"
	"github.com/1day0fmylife/Guardian/internal/wireguard"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("http://127.0.0.1:8080/healthz")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("load configuration", "error", err)
		os.Exit(1)
	}

	startupCtx, cancelStartup := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelStartup()

	st, err := store.Open(startupCtx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("open database", "error", err)
		os.Exit(1)
	}
	defer st.Close()

	if err := st.Migrate(startupCtx); err != nil {
		logger.Error("run database migrations", "error", err)
		os.Exit(1)
	}
	if err := st.SeedRBAC(startupCtx); err != nil {
		logger.Error("seed RBAC", "error", err)
		os.Exit(1)
	}

	api := httpapi.New(st, cfg.PublicURL, cfg.SessionTTL)
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           api.AdminHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wgProvider *wireguard.WGCtrlProvider
	if cfg.WireGuardInterface != "" {
		wgProvider, err = wireguard.NewWGCtrlProvider(cfg.WireGuardInterface)
		if err != nil {
			logger.Error("initialize WireGuard provider", "interface", cfg.WireGuardInterface, "error", err)
			os.Exit(1)
		}
		defer func() {
			if err := wgProvider.Close(); err != nil {
				logger.Error("close WireGuard provider", "error", err)
			}
		}()
		reconciler := wireguard.NewReconciler(st, wgProvider, cfg.WireGuardReconcileBatchSize)
		go wireguard.RunReconcileLoop(ctx, reconciler, cfg.WireGuardReconcileInterval, func(err error) {
			logger.Error("WireGuard reconcile", "interface", cfg.WireGuardInterface, "error", err)
		})
		logger.Info("WireGuard reconciler enabled",
			"interface", cfg.WireGuardInterface,
			"interval", cfg.WireGuardReconcileInterval,
			"batch_size", cfg.WireGuardReconcileBatchSize,
		)
	}

	go func() {
		logger.Info("guardian server started",
			"listen", cfg.ListenAddr,
			"environment", cfg.Environment,
			"database", st.Dialect(),
			"redis_enabled", cfg.RedisURL != "",
			"wireguard_local_provider", cfg.WireGuardInterface != "",
		)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("http server", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown", "error", err)
	}
}
