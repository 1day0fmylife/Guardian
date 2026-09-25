package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	ListenAddr  string
	DatabaseURL string
	RedisURL    string
	PublicURL   string
	Environment string
}

func Load() (Config, error) {
	cfg := Config{
		ListenAddr:  env("GUARDIAN_LISTEN_ADDR", ":8080"),
		DatabaseURL: env("GUARDIAN_DATABASE_URL", "sqlite://./data/guardian.db"),
		RedisURL:    strings.TrimSpace(os.Getenv("GUARDIAN_REDIS_URL")),
		PublicURL:   env("GUARDIAN_PUBLIC_URL", "http://localhost"),
		Environment: env("GUARDIAN_ENV", "development"),
	}

	if !strings.HasPrefix(cfg.DatabaseURL, "sqlite://") && !strings.HasPrefix(cfg.DatabaseURL, "postgres://") && !strings.HasPrefix(cfg.DatabaseURL, "postgresql://") {
		return Config{}, fmt.Errorf("unsupported GUARDIAN_DATABASE_URL scheme")
	}
	if cfg.ListenAddr == "" {
		return Config{}, fmt.Errorf("GUARDIAN_LISTEN_ADDR must not be empty")
	}
	return cfg, nil
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
