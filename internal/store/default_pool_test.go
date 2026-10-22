package store

import (
	"context"
	"testing"
)

func TestEnsureDefaultAddressPool(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.EnsureDefaultAddressPool(ctx, "10.88.0.0/22")
	if err != nil || !created {
		t.Fatalf("first seed: created=%v err=%v", created, err)
	}
	pools, err := s.ListAddressPools(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pools) != 1 || pools[0].CIDR != "10.88.0.0/22" || pools[0].Gateway != "10.88.0.1" || pools[0].Name != DefaultAddressPoolName {
		t.Fatalf("pools = %+v", pools)
	}

	created, err = s.EnsureDefaultAddressPool(ctx, "10.99.0.0/22")
	if err != nil || created {
		t.Fatalf("second seed must be a no-op: created=%v err=%v", created, err)
	}
	if pools, _ := s.ListAddressPools(ctx); len(pools) != 1 {
		t.Fatalf("expected one pool, got %d", len(pools))
	}
}
