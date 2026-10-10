// guardian-gateway-acl projects Guardian's service policy onto the nftables
// sets of the service gateway. It needs read access to the Guardian database
// and CAP_NET_ADMIN in the gateway network namespace, and nothing else.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/gatewayacl"
	"github.com/1day0fmylife/Guardian/internal/store"
)

func main() {
	var (
		table    = flag.String("table", "guardian_gw", "nftables inet table that declares the service sets")
		interval = flag.Duration("interval", 2*time.Second, "reconcile interval")
		staleTTL = flag.Duration("stale-ttl", 30*time.Second, "flush all sets when policy cannot be refreshed for this long")
		resync   = flag.Duration("resync", 30*time.Second, "re-apply an unchanged policy this often (recovers from ruleset reloads)")
		once     = flag.Bool("once", false, "synchronize once and exit")
		dryRun   = flag.Bool("dry-run", false, "print the nft script instead of applying it")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	dbURL := os.Getenv("GUARDIAN_DATABASE_URL")
	if dbURL == "" {
		fmt.Fprintln(os.Stderr, "GUARDIAN_DATABASE_URL is required")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	openCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	st, err := store.Open(openCtx, dbURL)
	cancel()
	if err != nil {
		logger.Error("open database", "error", err)
		os.Exit(1)
	}
	defer st.Close()

	var applier gatewayacl.Applier = gatewayacl.NftApplier{}
	if *dryRun {
		applier = printApplier{}
	}
	syncer := &gatewayacl.Syncer{
		Source: st, Applier: applier, Table: *table,
		ServiceIDs: domain.KnownServiceIDs(), StaleTTL: *staleTTL, ResyncInterval: *resync,
	}

	if *once {
		res, err := syncer.SyncOnce(ctx)
		if err != nil {
			logger.Error("sync", "error", err, "failed_closed", res.FailedClosed)
			os.Exit(1)
		}
		logger.Info("synced", "policy_revision", res.PolicyRevision, "targets", res.Targets, "changed", res.Changed)
		return
	}

	var lastErr string
	syncer.Run(ctx, *interval, func(res gatewayacl.SyncResult, err error) {
		switch {
		case err != nil:
			if msg := err.Error(); msg != lastErr {
				logger.Error("sync", "error", msg, "failed_closed", res.FailedClosed)
				lastErr = msg
			}
		case res.Changed:
			lastErr = ""
			logger.Info("service ACL updated", "policy_revision", res.PolicyRevision, "targets", res.Targets)
		default:
			lastErr = ""
		}
	})
}

type printApplier struct{}

func (printApplier) Apply(_ context.Context, script string) error {
	fmt.Print(script)
	return nil
}
