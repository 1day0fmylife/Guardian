package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/security"
)

func TestUserPasswordLifecycleAndListing(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		hash, err := security.HashPassword("an initial env password")
		if err != nil {
			t.Fatal(err)
		}
		root, created, err := st.EnsureBootstrapAdmin(ctx, "Root", "Root", hash)
		if err != nil || !created || !root.MustChangePassword {
			t.Fatalf("EnsureBootstrapAdmin = %+v, %v, %v", root, created, err)
		}
		if _, created, err := st.EnsureBootstrapAdmin(ctx, "other", "Other", hash); err != nil || created {
			t.Fatalf("second EnsureBootstrapAdmin = %v, %v", created, err)
		}

		keep, drop := "keep-session", "drop-session"
		for _, token := range []string{keep, drop} {
			if _, err := st.CreateSession(ctx, root.ID, security.HashToken(token), time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
		}
		if err := st.ChangeOwnPassword(ctx, root.ID, hash, security.HashToken(keep)); err != nil {
			t.Fatalf("ChangeOwnPassword: %v", err)
		}
		principal, err := st.PrincipalBySession(ctx, security.HashToken(keep), time.Now())
		if err != nil || principal.MustChangePassword {
			t.Fatalf("kept session principal = %+v, %v", principal, err)
		}
		if _, err := st.PrincipalBySession(ctx, security.HashToken(drop), time.Now()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("other session error = %v, want revoked", err)
		}

		for _, name := range []string{"b_user", "bxuser", "c-user"} {
			if _, err := st.CreateAdminUser(ctx, AdminUserCreate{Username: name, DisplayName: name, PasswordHash: hash, Roles: []string{"viewer"}, MustChangePassword: true}); err != nil {
				t.Fatal(err)
			}
		}
		users, total, err := st.ListUsersPage(ctx, UserListQuery{Search: "b_", Limit: 10})
		if err != nil || total != 1 || users[0].Username != "b_user" {
			t.Fatalf("escaped search = %+v total=%d err=%v", users, total, err)
		}
		users, total, err = st.ListUsersPage(ctx, UserListQuery{Status: "password_change", Sort: "username", Desc: true, Limit: 2})
		if err != nil || total != 3 || len(users) != 2 || users[0].Username != "c-user" {
			t.Fatalf("status+sort page = %+v total=%d err=%v", users, total, err)
		}
		if _, _, err := st.ListUsersPage(ctx, UserListQuery{Sort: "password_hash", Limit: 1}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid sort error = %v", err)
		}

		if _, err := st.SetUserDisabled(ctx, root.ID, true); !errors.Is(err, ErrLastSuperadmin) {
			t.Fatalf("lock last superadmin error = %v", err)
		}
		if err := st.SetAdminUserPassword(ctx, users[0].ID, hash); err != nil {
			t.Fatal(err)
		}
		reset, err := st.GetUser(ctx, users[0].ID)
		if err != nil || !reset.MustChangePassword {
			t.Fatalf("reset user = %+v, %v", reset, err)
		}
	})
}
