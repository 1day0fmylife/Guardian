package wireguard

import (
	"context"
	"errors"
	"testing"

	"github.com/1day0fmylife/Guardian/internal/domain"
)

type fakeRepository struct {
	items   []domain.WireGuardReconcileItem
	applied []string
	failed  []string
}

func (r *fakeRepository) ListPendingWireGuardReconciliations(context.Context, int) ([]domain.WireGuardReconcileItem, error) {
	return r.items, nil
}
func (r *fakeRepository) MarkWireGuardPeerApplied(_ context.Context, peerID string, revision int64) error {
	r.applied = append(r.applied, peerID)
	return nil
}
func (r *fakeRepository) MarkWireGuardPeerReconcileError(_ context.Context, peerID string, revision int64, message string) error {
	r.failed = append(r.failed, peerID)
	return nil
}

type fakeProvider struct {
	upserts []string
	removes []string
	failID  string
}

func (p *fakeProvider) UpsertPeer(_ context.Context, item domain.WireGuardReconcileItem) error {
	p.upserts = append(p.upserts, item.PeerID)
	if item.PeerID == p.failID {
		return errors.New("provider failure")
	}
	return nil
}
func (p *fakeProvider) RemovePeer(_ context.Context, item domain.WireGuardReconcileItem) error {
	p.removes = append(p.removes, item.PeerID)
	if item.PeerID == p.failID {
		return errors.New("provider failure")
	}
	return nil
}

func TestReconcilerRoutesDesiredStatesAndContinuesAfterFailure(t *testing.T) {
	repo := &fakeRepository{items: []domain.WireGuardReconcileItem{
		{PeerID: "connected", DesiredState: "connected", ConfigRevision: 1},
		{PeerID: "suspended", DesiredState: "disconnected", ConfigRevision: 2},
		{PeerID: "revoked", DesiredState: "revoked", ConfigRevision: 3},
		{PeerID: "broken", DesiredState: "connected", ConfigRevision: 4},
	}}
	provider := &fakeProvider{failID: "broken"}
	r := NewReconciler(repo, provider, 20)
	if err := r.RunOnce(context.Background()); err == nil {
		t.Fatal("RunOnce error = nil, want aggregated provider error")
	}
	if len(provider.upserts) != 2 || len(provider.removes) != 2 {
		t.Fatalf("provider calls: upserts=%v removes=%v", provider.upserts, provider.removes)
	}
	if len(repo.applied) != 3 {
		t.Fatalf("applied = %v, want 3 peers", repo.applied)
	}
	if len(repo.failed) != 1 || repo.failed[0] != "broken" {
		t.Fatalf("failed = %v", repo.failed)
	}
}
