package wireguard

import (
	"context"
	"errors"
	"fmt"

	"github.com/1day0fmylife/Guardian/internal/domain"
)

type Repository interface {
	ListPendingWireGuardReconciliations(context.Context, int) ([]domain.WireGuardReconcileItem, error)
	MarkWireGuardPeerApplied(context.Context, string, int64) error
	MarkWireGuardPeerReconcileError(context.Context, string, int64, string) error
}

type Provider interface {
	UpsertPeer(context.Context, domain.WireGuardReconcileItem) error
	RemovePeer(context.Context, domain.WireGuardReconcileItem) error
}

type Reconciler struct {
	repository Repository
	provider   Provider
	batchSize  int
}

func NewReconciler(repository Repository, provider Provider, batchSize int) *Reconciler {
	if batchSize <= 0 || batchSize > 500 {
		batchSize = 100
	}
	return &Reconciler{repository: repository, provider: provider, batchSize: batchSize}
}

func (r *Reconciler) RunOnce(ctx context.Context) error {
	items, err := r.repository.ListPendingWireGuardReconciliations(ctx, r.batchSize)
	if err != nil {
		return err
	}
	var reconcileErrors []error
	for _, item := range items {
		if err := r.reconcileOne(ctx, item); err != nil {
			reconcileErrors = append(reconcileErrors, err)
		}
	}
	return errors.Join(reconcileErrors...)
}

func (r *Reconciler) reconcileOne(ctx context.Context, item domain.WireGuardReconcileItem) error {
	var err error
	switch item.DesiredState {
	case "connected":
		err = r.provider.UpsertPeer(ctx, item)
	case "disconnected", "revoked":
		err = r.provider.RemovePeer(ctx, item)
	default:
		err = fmt.Errorf("unsupported desired WireGuard state %q", item.DesiredState)
	}
	if err != nil {
		_ = r.repository.MarkWireGuardPeerReconcileError(ctx, item.PeerID, item.ConfigRevision, err.Error())
		return fmt.Errorf("reconcile peer %s revision %d: %w", item.PeerID, item.ConfigRevision, err)
	}
	if err := r.repository.MarkWireGuardPeerApplied(ctx, item.PeerID, item.ConfigRevision); err != nil {
		return fmt.Errorf("confirm peer %s revision %d: %w", item.PeerID, item.ConfigRevision, err)
	}
	return nil
}
