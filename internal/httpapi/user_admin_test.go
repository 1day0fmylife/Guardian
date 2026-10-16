package httpapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/1day0fmylife/Guardian/internal/domain"
)

const tempPassword = "temporary password issued by admin"

func (h *apiHarness) createUser(username string, roles ...string) domain.User {
	h.t.Helper()
	var user domain.User
	h.mustDo(http.MethodPost, "/api/v1/users", "", h.admin, map[string]any{
		"username": username, "display_name": strings.ToUpper(username), "password": tempPassword, "roles": roles,
	}, http.StatusCreated, &user)
	return user
}

func (h *apiHarness) login(username, password string) (string, bool) {
	h.t.Helper()
	var out struct {
		Token              string `json:"token"`
		MustChangePassword bool   `json:"must_change_password"`
	}
	h.mustDo(http.MethodPost, "/api/v1/auth/login", "", "", map[string]any{"username": username, "password": password}, http.StatusOK, &out)
	return out.Token, out.MustChangePassword
}

func (h *apiHarness) auditActions(t *testing.T) []domain.AuditEvent {
	t.Helper()
	events, _, err := h.st.ListAuditEvents(context.Background(), 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func TestForcedPasswordChangeBlocksAPIUntilChanged(t *testing.T) {
	h := newAPIHarness(t)
	user := h.createUser("op", "operator")
	if !user.MustChangePassword {
		t.Fatal("admin-created user must be flagged for password change")
	}
	token, must := h.login("op", tempPassword)
	if !must {
		t.Fatal("login must report must_change_password")
	}
	parallel, _ := h.login("op", tempPassword)

	for _, path := range []string{"/api/v1/devices", "/api/v1/enrollments", "/api/v1/vpn-profiles"} {
		if code := h.errorCode(http.MethodGet, path, token, nil, http.StatusForbidden); code != "password_change_required" {
			t.Fatalf("%s code = %s", path, code)
		}
	}
	var me domain.Principal
	h.mustDo(http.MethodGet, "/api/v1/me", "", token, nil, http.StatusOK, &me)
	if !me.MustChangePassword {
		t.Fatal("/me must expose must_change_password")
	}

	change := func(current, next string, want int) string {
		if want == http.StatusNoContent {
			h.mustDo(http.MethodPost, "/api/v1/auth/password", "", token, map[string]any{"current_password": current, "new_password": next}, want, nil)
			return ""
		}
		return h.errorCode(http.MethodPost, "/api/v1/auth/password", token, map[string]any{"current_password": current, "new_password": next}, want)
	}
	if code := change("wrong current password", "a brand new password 1", http.StatusBadRequest); code != "invalid_current_password" {
		t.Fatalf("wrong current code = %s", code)
	}
	if code := change(tempPassword, tempPassword, http.StatusBadRequest); code != "invalid_password" {
		t.Fatalf("same password code = %s", code)
	}
	if code := change(tempPassword, "short", http.StatusBadRequest); code != "invalid_password" {
		t.Fatalf("short password code = %s", code)
	}
	change(tempPassword, "a brand new password 1", http.StatusNoContent)

	h.mustDo(http.MethodGet, "/api/v1/devices", "", token, nil, http.StatusOK, nil)
	h.mustDo(http.MethodGet, "/api/v1/me", "", token, nil, http.StatusOK, &me)
	if me.MustChangePassword {
		t.Fatal("flag must be cleared after change")
	}
	// The other session opened with the temporary password is revoked.
	h.mustDo(http.MethodGet, "/api/v1/me", "", parallel, nil, http.StatusUnauthorized, nil)
	h.mustDo(http.MethodPost, "/api/v1/auth/login", "", "", map[string]any{"username": "op", "password": tempPassword}, http.StatusUnauthorized, nil)
	if _, must := h.login("op", "a brand new password 1"); must {
		t.Fatal("must_change_password persisted after change")
	}

	// Logout stays available while a change is pending.
	h.mustDo(http.MethodPost, "/api/v1/users/"+user.ID+"/password", "", h.admin, map[string]any{"password": "second temporary password"}, http.StatusNoContent, nil)
	pending, must := h.login("op", "second temporary password")
	if !must {
		t.Fatal("admin reset must force a password change")
	}
	h.mustDo(http.MethodPost, "/api/v1/auth/logout", "", pending, nil, http.StatusNoContent, nil)

	var sawChange, sawFailure bool
	for _, event := range h.auditActions(t) {
		sawChange = sawChange || (event.Action == "auth.password.change" && event.ResourceID == user.ID)
		sawFailure = sawFailure || event.Action == "auth.password.change_failed"
		for _, secret := range []string{tempPassword, "a brand new password 1", "second temporary password"} {
			if strings.Contains(event.Details, secret) {
				t.Fatalf("audit %s leaked a password", event.Action)
			}
		}
	}
	if !sawChange || !sawFailure {
		t.Fatalf("missing password audit events (change=%v failure=%v)", sawChange, sawFailure)
	}
}

func TestBuiltInRolesBoundUserAdministration(t *testing.T) {
	h := newAPIHarness(t)
	viewer := h.userToken("viewer1", "viewer")
	auditor := h.userToken("auditor1", "auditor")
	admin := h.userToken("admin1", "admin")
	body := map[string]any{"username": "x", "display_name": "x", "password": tempPassword, "roles": []string{"viewer"}}

	h.mustDo(http.MethodGet, "/api/v1/users", "", viewer, nil, http.StatusForbidden, nil)
	h.mustDo(http.MethodGet, "/api/v1/users", "", auditor, nil, http.StatusOK, nil)
	h.mustDo(http.MethodGet, "/api/v1/roles", "", auditor, nil, http.StatusOK, nil)
	h.mustDo(http.MethodPost, "/api/v1/users", "", auditor, body, http.StatusForbidden, nil)
	h.mustDo(http.MethodPost, "/api/v1/users", "", admin, body, http.StatusCreated, nil)

	// admin cannot mint or escalate to superadmin, nor act on a superadmin.
	escalate := map[string]any{"username": "y", "display_name": "y", "password": tempPassword, "roles": []string{"superadmin"}}
	if code := h.errorCode(http.MethodPost, "/api/v1/users", admin, escalate, http.StatusForbidden); code != "privilege_escalation" {
		t.Fatalf("create superadmin code = %s", code)
	}
	var users struct {
		Items []domain.User `json:"items"`
	}
	h.mustDo(http.MethodGet, "/api/v1/users?q=root", "", admin, nil, http.StatusOK, &users)
	root := users.Items[0]
	if code := h.errorCode(http.MethodPost, "/api/v1/users/"+root.ID+"/password", admin, map[string]any{"password": "hijack attempt password"}, http.StatusForbidden); code != "privilege_escalation" {
		t.Fatalf("reset superadmin code = %s", code)
	}
	if code := h.errorCode(http.MethodPost, "/api/v1/users/"+root.ID+"/lock", admin, nil, http.StatusForbidden); code != "privilege_escalation" {
		t.Fatalf("lock superadmin code = %s", code)
	}
	h.mustDo(http.MethodGet, "/api/v1/users?q=admin1", "", admin, nil, http.StatusOK, &users)
	self := users.Items[0]
	if code := h.errorCode(http.MethodPatch, "/api/v1/users/"+self.ID, admin, map[string]any{"display_name": "a", "roles": []string{"admin", "superadmin"}}, http.StatusForbidden); code != "privilege_escalation" {
		t.Fatalf("self escalation code = %s", code)
	}
}

func TestLastSuperadminCannotBeLockedOrDemoted(t *testing.T) {
	h := newAPIHarness(t)
	var me domain.Principal
	h.mustDo(http.MethodGet, "/api/v1/me", "", h.admin, nil, http.StatusOK, &me)
	second := h.createUser("second-root", "superadmin")
	secondToken := h.userTokenFor("second-root")

	// Root demotes itself only while another active superadmin exists.
	h.mustDo(http.MethodPost, "/api/v1/users/"+second.ID+"/lock", "", h.admin, nil, http.StatusOK, nil)
	if code := h.errorCode(http.MethodPatch, "/api/v1/users/"+me.UserID, h.admin, map[string]any{"display_name": "Root", "roles": []string{"admin"}}, http.StatusConflict); code != "last_superadmin" {
		t.Fatalf("demote last superadmin code = %s", code)
	}
	// Locked user lost its session and cannot sign in.
	h.mustDo(http.MethodGet, "/api/v1/me", "", secondToken, nil, http.StatusUnauthorized, nil)
	h.mustDo(http.MethodPost, "/api/v1/auth/login", "", "", map[string]any{"username": "second-root", "password": "a replaced personal password for second-root"}, http.StatusUnauthorized, nil)

	h.mustDo(http.MethodPost, "/api/v1/users/"+second.ID+"/unlock", "", h.admin, nil, http.StatusOK, nil)
	secondToken, _ = h.login("second-root", "a replaced personal password for second-root")
	// second-root may lock root now, but then cannot lock itself / be the last.
	h.mustDo(http.MethodPost, "/api/v1/users/"+me.UserID+"/lock", "", secondToken, nil, http.StatusOK, nil)
	if code := h.errorCode(http.MethodPost, "/api/v1/users/"+second.ID+"/lock", secondToken, nil, http.StatusConflict); code != "cannot_disable_self" {
		t.Fatalf("self lock code = %s", code)
	}
	if code := h.errorCode(http.MethodPatch, "/api/v1/users/"+second.ID, secondToken, map[string]any{"display_name": "s", "roles": []string{"admin"}}, http.StatusConflict); code != "last_superadmin" {
		t.Fatalf("demote remaining superadmin code = %s", code)
	}

	actions := map[string]bool{}
	for _, event := range h.auditActions(t) {
		actions[event.Action] = true
	}
	for _, want := range []string{"user.create", "user.lock", "user.unlock", "auth.password.change"} {
		if !actions[want] {
			t.Fatalf("missing audit action %s in %v", want, actions)
		}
	}
}

// userTokenFor completes the forced change for an already created user.
func (h *apiHarness) userTokenFor(username string) string {
	h.t.Helper()
	token, _ := h.login(username, tempPassword)
	h.mustDo(http.MethodPost, "/api/v1/auth/password", "", token, map[string]any{
		"current_password": tempPassword, "new_password": "a replaced personal password for " + username,
	}, http.StatusNoContent, nil)
	return token
}

func TestUserCollectionPaginationFilterSort(t *testing.T) {
	h := newAPIHarness(t)
	for _, name := range []string{"alpha", "bravo", "charlie", "delta"} {
		h.createUser(name, "viewer")
	}
	h.createUser("echo", "auditor")
	var page struct {
		Items  []domain.User `json:"items"`
		Total  int           `json:"total"`
		Limit  int           `json:"limit"`
		Offset int           `json:"offset"`
	}
	h.mustDo(http.MethodGet, "/api/v1/users?limit=2&offset=1&sort=username", "", h.admin, nil, http.StatusOK, &page)
	if page.Total != 6 || len(page.Items) != 2 || page.Items[0].Username != "bravo" || page.Items[1].Username != "charlie" {
		t.Fatalf("page = %+v", page)
	}
	h.mustDo(http.MethodGet, "/api/v1/users?sort=-username&limit=1", "", h.admin, nil, http.StatusOK, &page)
	if page.Items[0].Username != "root" {
		t.Fatalf("desc sort first = %s", page.Items[0].Username)
	}
	h.mustDo(http.MethodGet, "/api/v1/users?role=auditor", "", h.admin, nil, http.StatusOK, &page)
	if page.Total != 1 || page.Items[0].Username != "echo" {
		t.Fatalf("role filter = %+v", page)
	}
	h.mustDo(http.MethodGet, "/api/v1/users?q=HAR", "", h.admin, nil, http.StatusOK, &page)
	if page.Total != 1 || page.Items[0].Username != "charlie" {
		t.Fatalf("search = %+v", page)
	}
	h.mustDo(http.MethodGet, "/api/v1/users?status=password_change", "", h.admin, nil, http.StatusOK, &page)
	if page.Total != 5 {
		t.Fatalf("password_change filter total = %d", page.Total)
	}
	h.mustDo(http.MethodGet, "/api/v1/users?q=%25", "", h.admin, nil, http.StatusOK, &page)
	if page.Total != 0 {
		t.Fatalf("LIKE wildcard was not escaped: %d", page.Total)
	}
	if code := h.errorCode(http.MethodGet, "/api/v1/users?sort=password_hash", h.admin, nil, http.StatusBadRequest); code != "invalid_query" {
		t.Fatalf("bad sort code = %s", code)
	}
	_, raw := h.do(http.MethodGet, "/api/v1/users", "Bearer", h.admin, nil)
	if strings.Contains(string(raw), "argon2id") || strings.Contains(string(raw), "password_hash") {
		t.Fatal("user listing exposed password hashes")
	}
}

func TestManualBootstrapRemainsCompatible(t *testing.T) {
	h := newAPIHarness(t)
	// Harness bootstrapped "root" via POST /auth/bootstrap: the operator chose
	// the password, so no forced change, and a second bootstrap is refused.
	var me domain.Principal
	h.mustDo(http.MethodGet, "/api/v1/me", "", h.admin, nil, http.StatusOK, &me)
	if me.MustChangePassword {
		t.Fatal("manual bootstrap must not force a password change")
	}
	if code := h.errorCode(http.MethodPost, "/api/v1/auth/bootstrap", "", map[string]any{"username": "x", "password": "another bootstrap password"}, http.StatusConflict); code != "already_bootstrapped" {
		t.Fatalf("second bootstrap code = %s", code)
	}
	var status map[string]bool
	h.mustDo(http.MethodGet, "/api/v1/setup/status", "", "", nil, http.StatusOK, &status)
	if status["bootstrap_required"] {
		t.Fatal("bootstrap_required after bootstrap")
	}
}
