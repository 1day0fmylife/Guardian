package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr                  string
	DatabaseURL                 string
	RedisURL                    string
	PublicURL                   string
	Environment                 string
	SessionTTL                  time.Duration
	WireGuardInterface          string
	WireGuardReconcileInterval  time.Duration
	WireGuardReconcileBatchSize int
}

func Load() (Config, error) {
	sessionTTL, err := time.ParseDuration(env("GUARDIAN_SESSION_TTL", "12h"))
	if err != nil || sessionTTL < 5*time.Minute || sessionTTL > 30*24*time.Hour {
		return Config{}, fmt.Errorf("GUARDIAN_SESSION_TTL must be between 5m and 720h")
	}
	reconcileInterval, err := time.ParseDuration(env("GUARDIAN_WIREGUARD_RECONCILE_INTERVAL", "5s"))
	if err != nil || reconcileInterval < 250*time.Millisecond || reconcileInterval > 5*time.Minute {
		return Config{}, fmt.Errorf("GUARDIAN_WIREGUARD_RECONCILE_INTERVAL must be between 250ms and 5m")
	}
	reconcileBatch, err := strconv.Atoi(env("GUARDIAN_WIREGUARD_RECONCILE_BATCH", "100"))
	if err != nil || reconcileBatch < 1 || reconcileBatch > 500 {
		return Config{}, fmt.Errorf("GUARDIAN_WIREGUARD_RECONCILE_BATCH must be between 1 and 500")
	}

	cfg := Config{
		ListenAddr:                  env("GUARDIAN_LISTEN_ADDR", ":8080"),
		DatabaseURL:                 env("GUARDIAN_DATABASE_URL", "sqlite://./data/guardian.db"),
		RedisURL:                    strings.TrimSpace(os.Getenv("GUARDIAN_REDIS_URL")),
		PublicURL:                   strings.TrimRight(env("GUARDIAN_PUBLIC_URL", "http://localhost"), "/"),
		Environment:                 env("GUARDIAN_ENV", "development"),
		SessionTTL:                  sessionTTL,
		WireGuardInterface:          strings.TrimSpace(os.Getenv("GUARDIAN_WIREGUARD_INTERFACE")),
		WireGuardReconcileInterval:  reconcileInterval,
		WireGuardReconcileBatchSize: reconcileBatch,
	}

	if !strings.HasPrefix(cfg.DatabaseURL, "sqlite://") &&
		!strings.HasPrefix(cfg.DatabaseURL, "postgres://") &&
		!strings.HasPrefix(cfg.DatabaseURL, "postgresql://") {
		return Config{}, fmt.Errorf("unsupported GUARDIAN_DATABASE_URL scheme")
	}
	if cfg.ListenAddr == "" {
		return Config{}, fmt.Errorf("GUARDIAN_LISTEN_ADDR must not be empty")
	}
	if !strings.HasPrefix(cfg.PublicURL, "http://") && !strings.HasPrefix(cfg.PublicURL, "https://") {
		return Config{}, fmt.Errorf("GUARDIAN_PUBLIC_URL must use http or https")
	}
	return cfg, nil
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
