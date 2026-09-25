package wireguard

import (
	"context"
	"time"
)

func RunReconcileLoop(ctx context.Context, reconciler *Reconciler, interval time.Duration, reportError func(error)) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	run := func() {
		if err := reconciler.RunOnce(ctx); err != nil && reportError != nil {
			reportError(err)
		}
	}

	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
