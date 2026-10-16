package adminbootstrap

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/config"
	"github.com/1day0fmylife/Guardian/internal/rbac"
	"github.com/1day0fmylife/Guardian/internal/security"
	"github.com/1day0fmylife/Guardian/internal/store"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, "sqlite://"+t.TempDir()+"/guardian.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := st.SeedRBAC(ctx); err != nil {
		t.Fatalf("SeedRBAC: %v", err)
	}
	return st
}

func TestEnsureCreatesForcedChangeSuperadminOnceWithoutLoggingPassword(t *testing.T) {
	const secret = "initial-env-password-1234"
	ctx := context.Background()
	st := newStore(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	admin := config.BootstrapAdmin{Username: "admin", DisplayName: "Administrator", Password: secret}

	created, err := Ensure(ctx, st, admin, logger)
	if err != nil || !created {
		t.Fatalf("first Ensure = %v, %v", created, err)
	}
	// Restart with a different env password must not touch the account.
	created, err = Ensure(ctx, st, config.BootstrapAdmin{Username: "other", Password: "a different env password"}, logger)
	if err != nil || created {
		t.Fatalf("second Ensure = %v, %v; want idempotent skip", created, err)
	}
	if count, _ := st.UserCount(ctx); count != 1 {
		t.Fatalf("user count = %d, want 1", count)
	}

	users, err := st.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	user := users[0]
	if user.Username != "admin" || !user.MustChangePassword || len(user.Roles) != 1 || user.Roles[0] != "superadmin" {
		t.Fatalf("bootstrap user = %+v", user)
	}
	hash, err := st.PasswordHashForUser(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := security.VerifyPassword(secret, hash); !ok {
		t.Fatal("first env password was not kept")
	}
	if strings.Contains(hash, secret) {
		t.Fatal("password stored in plaintext")
	}

	token := "bootstrap-session"
	if _, err := st.CreateSession(ctx, user.ID, security.HashToken(token), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	principal, err := st.PrincipalBySession(ctx, security.HashToken(token), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !principal.MustChangePassword || !rbac.Covers(principal.Permissions, rbac.AllPermissions) {
		t.Fatalf("principal = %+v", principal)
	}

	events, _, err := st.ListAuditEvents(ctx, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != "auth.bootstrap.env" || events[0].ResourceID != user.ID {
		t.Fatalf("audit events = %+v", events)
	}
	for _, event := range events {
		if strings.Contains(event.Details, secret) {
			t.Fatal("audit details leaked the password")
		}
	}
	if strings.Contains(logs.String(), secret) || strings.Contains(logs.String(), "a different env password") {
		t.Fatalf("logs leaked a password: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "bootstrap administrator created") {
		t.Fatalf("missing creation log: %s", logs.String())
	}
}

func TestEnsureIsNoopWithoutPasswordOrWhenUsersExist(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	if created, err := Ensure(ctx, st, config.BootstrapAdmin{Username: "admin"}, logger); err != nil || created {
		t.Fatalf("Ensure without password = %v, %v", created, err)
	}
	hash, _ := security.HashPassword("a manual bootstrap password")
	if _, err := st.CreateBootstrapUser(ctx, "manual", "Manual", hash); err != nil {
		t.Fatal(err)
	}
	if created, err := Ensure(ctx, st, config.BootstrapAdmin{Username: "admin", Password: "an env password value"}, logger); err != nil || created {
		t.Fatalf("Ensure after manual bootstrap = %v, %v", created, err)
	}
	users, _ := st.ListUsers(ctx)
	if len(users) != 1 || users[0].Username != "manual" || users[0].MustChangePassword {
		t.Fatalf("users = %+v", users)
	}
}
