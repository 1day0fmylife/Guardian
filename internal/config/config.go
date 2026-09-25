package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	ListenAddr  string
	DatabaseURL string
	RedisURL    string
	PublicURL   string
	Environment string
	SessionTTL  time.Duration
}

func Load() (Config, error) {
	sessionTTL, err := time.ParseDuration(env("GUARDIAN_SESSION_TTL", "12h"))
	if err != nil || sessionTTL < 5*time.Minute || sessionTTL > 30*24*time.Hour {
		return Config{}, fmt.Errorf("GUARDIAN_SESSION_TTL must be between 5m and 720h")
	}

	cfg := Config{
		ListenAddr:  env("GUARDIAN_LISTEN_ADDR", ":8080"),
		DatabaseURL: env("GUARDIAN_DATABASE_URL", "sqlite://./data/guardian.db"),
		RedisURL:    strings.TrimSpace(os.Getenv("GUARDIAN_REDIS_URL")),
		PublicURL:   strings.TrimRight(env("GUARDIAN_PUBLIC_URL", "http://localhost"), "/"),
		Environment: env("GUARDIAN_ENV", "development"),
		SessionTTL:  sessionTTL,
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
