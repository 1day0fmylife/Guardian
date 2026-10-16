// Package adminbootstrap creates the first Guardian superadmin from deployment
// configuration (.env / *_FILE secrets) on an empty database.
package adminbootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/1day0fmylife/Guardian/internal/config"
	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/security"
	"github.com/1day0fmylife/Guardian/internal/store"
)

// Ensure creates the configured administrator when no user exists yet. It is
// idempotent across restarts and replicas: once any user exists it does
// nothing, so changing the env password later never resets an account. The
// created account must change its password on first sign-in. The password is
// never logged.
func Ensure(ctx context.Context, st *store.Store, admin config.BootstrapAdmin, logger *slog.Logger) (bool, error) {
	if !admin.Enabled() {
		return false, nil
	}
	count, err := st.UserCount(ctx)
	if err != nil {
		return false, err
	}
	if count != 0 {
		logger.Info("bootstrap administrator skipped: users already exist")
		return false, nil
	}
	hash, err := security.HashPassword(admin.Password)
	if err != nil {
		return false, fmt.Errorf("bootstrap administrator password rejected by policy")
	}
	user, created, err := st.EnsureBootstrapAdmin(ctx, admin.Username, admin.DisplayName, hash)
	if err != nil {
		return false, fmt.Errorf("create bootstrap administrator: %w", err)
	}
	if !created {
		logger.Info("bootstrap administrator skipped: users already exist")
		return false, nil
	}
	details, _ := json.Marshal(map[string]any{"username": user.Username, "source": "environment", "must_change_password": true})
	if err := st.AppendAudit(ctx, domain.AuditEvent{
		ActorUserID:  user.ID,
		Action:       "auth.bootstrap.env",
		ResourceType: "user",
		ResourceID:   user.ID,
		Details:      string(details),
	}); err != nil {
		return true, fmt.Errorf("audit bootstrap administrator: %w", err)
	}
	logger.Info("bootstrap administrator created; password change required at first sign-in", "username", user.Username)
	return true, nil
}
