package store

import (
	"context"
	"strings"
	"testing"

	"github.com/1day0fmylife/Guardian/internal/domain"
)

func TestConnectionRequestPolicyGrantRevokeAndAudit(t *testing.T) {
	forEachDialect(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		meta := testActor(t, st)
		device, _ := enrollActiveDevice(t, st)
		input := davInput(true)
		input.DisplayName = "ACS"
		input.InternalDNSName = "acs.internal"
		def, err := st.GetServiceDefinition(ctx, domain.ServiceSunkarCWMPACS)
		if err != nil {
			t.Fatal(err)
		}
		if def.ConnectionRequest != nil {
			t.Fatal("legacy/default service grants CR")
		}
		input.ConnectionRequest = &domain.ConnectionRequestPolicy{SourceAddress: "10.78.0.12", Port: 7547}
		first, err := st.UpdateServiceDefinition(ctx, meta, def.ID, def.Revision, input)
		if err != nil {
			t.Fatal(err)
		}
		again, err := st.UpdateServiceDefinition(ctx, meta, def.ID, first.Definition.Revision, input)
		if err != nil || again.Changed || again.PolicyRevision != first.PolicyRevision {
			t.Fatalf("idempotent callback update = %+v, %v", again, err)
		}
		policy, err := st.DeviceServicePolicy(ctx, device.ID)
		if err != nil || len(policy.Services) != 0 {
			t.Fatalf("without grant = %+v, %v", policy, err)
		}
		grant, err := st.SetServiceGrant(ctx, meta, def.ID, domain.ScopeDevice, device.ID, domain.GrantEffectAllow)
		if err != nil {
			t.Fatal(err)
		}
		policy, err = st.DeviceServicePolicy(ctx, device.ID)
		if err != nil || len(policy.Services) != 1 || policy.Services[0].ConnectionRequest == nil {
			t.Fatalf("granted callback = %+v, %v", policy, err)
		}
		snap, err := st.ServiceAccessSnapshot(ctx)
		if err != nil || len(snap.Targets) != 1 || snap.Targets[0].CWMPConnectionRequestSource != "10.78.0.12" {
			t.Fatalf("callback snapshot = %+v, %v", snap, err)
		}
		input.ConnectionRequest = nil
		cleared, err := st.UpdateServiceDefinition(ctx, meta, def.ID, first.Definition.Revision, input)
		if err != nil {
			t.Fatal(err)
		}
		if cleared.PolicyRevision <= grant.PolicyRevision || cleared.Definition.ConnectionRequest != nil {
			t.Fatal("callback revoke did not advance revision")
		}
		policy, err = st.DeviceServicePolicy(ctx, device.ID)
		if err != nil || len(policy.Services) != 1 || policy.Services[0].ConnectionRequest != nil {
			t.Fatalf("callback revoked but ACS remains = %+v, %v", policy, err)
		}
		count, actor := countAudit(t, st, "service.update", def.ID)
		if count != 2 || actor != meta.ActorUserID {
			t.Fatalf("callback audit count/actor = %d/%s", count, actor)
		}
		rows, err := st.db.QueryContext(ctx, st.q("SELECT details FROM audit_events WHERE action = ? AND resource_id = ?"), "service.update", def.ID)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { // Read-only fixture cleanup; Rows.Err below checks iteration failures.
			_ = rows.Close()
		}()
		found := false
		for rows.Next() {
			var detail string
			if err := rows.Scan(&detail); err != nil {
				t.Fatal(err)
			}
			found = found || strings.Contains(detail, "10.78.0.12")
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if !found {
			t.Fatal("callback policy absent from atomic audit")
		}
	})
}

func TestConnectionRequestRejectsUnsafeAndForeignServices(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	meta := testActor(t, st)
	for _, source := range []string{"8.8.8.8", "127.0.0.1", "10.78.0.0/24", "::ffff:10.78.0.12", "10.78.0.12;accept"} {
		input := davInput(true)
		input.ConnectionRequest = &domain.ConnectionRequestPolicy{SourceAddress: source, Port: 7547}
		if _, err := st.UpdateServiceDefinition(ctx, meta, domain.ServiceSunkarCWMPACS, 1, input); err == nil {
			t.Errorf("accepted callback source %q", source)
		}
	}
	input := davInput(true)
	input.ConnectionRequest = &domain.ConnectionRequestPolicy{SourceAddress: "10.78.0.12", Port: 7557}
	if _, err := st.UpdateServiceDefinition(ctx, meta, domain.ServiceSunkarCWMPACS, 1, input); err == nil {
		t.Fatal("accepted NBI port")
	}
	input.ConnectionRequest.Port = 7547
	if _, err := st.UpdateServiceDefinition(ctx, meta, domain.ServiceSunkarDAV, 1, input); err == nil {
		t.Fatal("accepted callback on DAV")
	}
}
