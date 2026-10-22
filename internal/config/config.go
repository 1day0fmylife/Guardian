package config

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr                  string
	MetricsListenAddr           string
	GatewayProbeAddress         string
	TelemetryRetentionAge       time.Duration
	DatabaseURL                 string
	RedisURL                    string
	PublicURL                   string
	Environment                 string
	SessionTTL                  time.Duration
	WireGuardInterface          string
	ServiceACLRequired          bool
	WireGuardReconcileInterval  time.Duration
	WireGuardReconcileBatchSize int
	BootstrapAdmin              BootstrapAdmin
	// DeviceTrustBundleFile is served to devices as the service CA trust
	// bundle (CA rollover with cross-certificates). Empty: no bundle.
	DeviceTrustBundleFile string
	// DefaultAddressPool is the tunnel CIDR seeded when the database has no
	// address pools. Empty disables seeding.
	DefaultAddressPool string
}

// DefaultAddressPoolCIDR gives 1,024 addresses: enough for the initial
// ~1,000-device target plus the gateway.
const DefaultAddressPoolCIDR = "10.88.0.0/22"

// BootstrapAdmin describes the first superadmin created on an empty database.
// Password is a secret: never log it or include it in errors.
type BootstrapAdmin struct {
	Username    string
	DisplayName string
	Password    string
}

// Enabled reports whether deployment configuration requests an initial admin.
func (b BootstrapAdmin) Enabled() bool { return b.Password != "" }

// String keeps the password out of accidental %v/%s formatting.
func (b BootstrapAdmin) String() string {
	return fmt.Sprintf("BootstrapAdmin{Username:%q, Password:<redacted>}", b.Username)
}

// GoString keeps the password out of %#v formatting.
func (b BootstrapAdmin) GoString() string { return b.String() }

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

	aclRequired, err := strconv.ParseBool(env("GUARDIAN_SERVICE_ACL_REQUIRED", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("GUARDIAN_SERVICE_ACL_REQUIRED must be a boolean")
	}
	metricsAddr := strings.TrimSpace(os.Getenv("GUARDIAN_METRICS_LISTEN_ADDR"))
	if metricsAddr != "" {
		host, port, err := net.SplitHostPort(metricsAddr)
		ip, ipErr := netip.ParseAddr(host)
		number, portErr := strconv.Atoi(port)
		if err != nil || ipErr != nil || !ip.IsLoopback() || portErr != nil || number < 1 || number > 65535 {
			return Config{}, fmt.Errorf("GUARDIAN_METRICS_LISTEN_ADDR must use a literal loopback IP and valid port")
		}
	}
	probe := strings.TrimSpace(os.Getenv("GUARDIAN_GATEWAY_PROBE_ADDRESS"))
	if probe != "" {
		host, port, err := net.SplitHostPort(probe)
		number, portErr := strconv.Atoi(port)
		if err != nil || host == "" || portErr != nil || number < 1 || number > 65535 {
			return Config{}, fmt.Errorf("GUARDIAN_GATEWAY_PROBE_ADDRESS must be host:port")
		}
	}
	age, err := time.ParseDuration(env("GUARDIAN_TELEMETRY_RETENTION_AGE", "0s"))
	if err != nil || age < 0 || (age > 0 && (age < 24*time.Hour || age > 3650*24*time.Hour)) {
		return Config{}, fmt.Errorf("GUARDIAN_TELEMETRY_RETENTION_AGE must be 0s (disabled) or between 24h and 87600h")
	}
	defaultPool := env("GUARDIAN_DEFAULT_ADDRESS_POOL", DefaultAddressPoolCIDR)
	if strings.EqualFold(defaultPool, "off") {
		defaultPool = ""
	}
	if defaultPool != "" {
		prefix, err := netip.ParsePrefix(defaultPool)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 16 || prefix.Bits() > 30 {
			return Config{}, fmt.Errorf("GUARDIAN_DEFAULT_ADDRESS_POOL must be an IPv4 CIDR between /16 and /30, or off")
		}
		defaultPool = prefix.Masked().String()
	}
	bootstrapAdmin, err := loadBootstrapAdmin()
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		BootstrapAdmin:              bootstrapAdmin,
		DefaultAddressPool:          defaultPool,
		MetricsListenAddr:           metricsAddr,
		GatewayProbeAddress:         probe,
		TelemetryRetentionAge:       age,
		ServiceACLRequired:          aclRequired,
		ListenAddr:                  env("GUARDIAN_LISTEN_ADDR", ":8080"),
		DatabaseURL:                 env("GUARDIAN_DATABASE_URL", "sqlite://./data/guardian.db"),
		RedisURL:                    strings.TrimSpace(os.Getenv("GUARDIAN_REDIS_URL")),
		PublicURL:                   strings.TrimRight(env("GUARDIAN_PUBLIC_URL", "http://localhost"), "/"),
		DeviceTrustBundleFile:       strings.TrimSpace(os.Getenv("GUARDIAN_DEVICE_TRUST_BUNDLE_FILE")),
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

// loadBootstrapAdmin reads GUARDIAN_BOOTSTRAP_ADMIN_* settings. The password
// may be supplied inline or via *_FILE (Docker/systemd secrets); not both.
func loadBootstrapAdmin() (BootstrapAdmin, error) {
	password := os.Getenv("GUARDIAN_BOOTSTRAP_ADMIN_PASSWORD")
	passwordFile := strings.TrimSpace(os.Getenv("GUARDIAN_BOOTSTRAP_ADMIN_PASSWORD_FILE"))
	if password != "" && passwordFile != "" {
		return BootstrapAdmin{}, fmt.Errorf("set only one of GUARDIAN_BOOTSTRAP_ADMIN_PASSWORD and GUARDIAN_BOOTSTRAP_ADMIN_PASSWORD_FILE")
	}
	if passwordFile != "" {
		raw, err := os.ReadFile(passwordFile)
		if err != nil {
			// The path is not secret; the file content is never echoed.
			return BootstrapAdmin{}, fmt.Errorf("read GUARDIAN_BOOTSTRAP_ADMIN_PASSWORD_FILE: %w", err)
		}
		password = strings.TrimRight(string(raw), "\r\n")
		if password == "" {
			return BootstrapAdmin{}, fmt.Errorf("GUARDIAN_BOOTSTRAP_ADMIN_PASSWORD_FILE is empty")
		}
	}
	username := strings.ToLower(env("GUARDIAN_BOOTSTRAP_ADMIN_USERNAME", "admin"))
	if password != "" {
		if len(username) > 64 || strings.ContainsAny(username, " \t\r\n") {
			return BootstrapAdmin{}, fmt.Errorf("GUARDIAN_BOOTSTRAP_ADMIN_USERNAME must be 1-64 characters without whitespace")
		}
		if len(password) < 12 || len(password) > 1024 {
			return BootstrapAdmin{}, fmt.Errorf("GUARDIAN_BOOTSTRAP_ADMIN_PASSWORD must contain 12-1024 characters")
		}
	}
	return BootstrapAdmin{
		Username:    username,
		DisplayName: env("GUARDIAN_BOOTSTRAP_ADMIN_DISPLAY_NAME", "Administrator"),
		Password:    password,
	}, nil
}
