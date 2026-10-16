package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapAdminFromEnvironment(t *testing.T) {
	const secret = "a bootstrap secret from env"
	t.Setenv("GUARDIAN_BOOTSTRAP_ADMIN_USERNAME", "Root")
	t.Setenv("GUARDIAN_BOOTSTRAP_ADMIN_PASSWORD", secret)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.BootstrapAdmin.Enabled() || cfg.BootstrapAdmin.Username != "root" || cfg.BootstrapAdmin.Password != secret {
		t.Fatalf("bootstrap admin = %s", cfg.BootstrapAdmin)
	}
	for _, rendered := range []string{fmt.Sprint(cfg.BootstrapAdmin), fmt.Sprintf("%v %+v %#v %s", cfg.BootstrapAdmin, cfg.BootstrapAdmin, cfg.BootstrapAdmin, cfg.BootstrapAdmin)} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("formatted bootstrap admin leaked password: %s", rendered)
		}
	}
}

func TestBootstrapAdminDisabledByDefault(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BootstrapAdmin.Enabled() {
		t.Fatal("bootstrap admin must be opt-in")
	}
}

func TestBootstrapAdminPasswordFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin-password")
	if err := os.WriteFile(path, []byte("a password stored in a file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDIAN_BOOTSTRAP_ADMIN_PASSWORD_FILE", path)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BootstrapAdmin.Password != "a password stored in a file" || cfg.BootstrapAdmin.Username != "admin" {
		t.Fatalf("password file not trimmed or default username missing: %s", cfg.BootstrapAdmin)
	}
}

func TestBootstrapAdminRejectsInvalidSettingsWithoutEchoingSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin-password")
	if err := os.WriteFile(path, []byte("another long password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]map[string]string{
		"both":      {"GUARDIAN_BOOTSTRAP_ADMIN_PASSWORD": "inline password value", "GUARDIAN_BOOTSTRAP_ADMIN_PASSWORD_FILE": path},
		"short":     {"GUARDIAN_BOOTSTRAP_ADMIN_PASSWORD": "short-pw"},
		"missing":   {"GUARDIAN_BOOTSTRAP_ADMIN_PASSWORD_FILE": filepath.Join(t.TempDir(), "absent")},
		"bad-login": {"GUARDIAN_BOOTSTRAP_ADMIN_PASSWORD": "inline password value", "GUARDIAN_BOOTSTRAP_ADMIN_USERNAME": "bad user"},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			for key, value := range env {
				t.Setenv(key, value)
			}
			_, err := Load()
			if err == nil {
				t.Fatal("Load accepted invalid bootstrap admin settings")
			}
			if pw := env["GUARDIAN_BOOTSTRAP_ADMIN_PASSWORD"]; pw != "" && strings.Contains(err.Error(), pw) {
				t.Fatalf("error leaked password: %v", err)
			}
		})
	}
}
