// guardian-gateway-acl projects Guardian's service policy onto the nftables
// sets of the service gateway. It needs read access to the Guardian database
// (plus UPDATE on service_acl_state) and CAP_NET_ADMIN in the gateway network namespace, and nothing else.
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
	"github.com/1day0fmylife/Guardian/internal/wireguard"
)

func main() {
	var (
		table          = flag.String("table", "guardian_gw", "nftables inet table that declares the service sets")
		interval       = flag.Duration("interval", 2*time.Second, "reconcile interval")
		staleTTL       = flag.Duration("stale-ttl", 30*time.Second, "flush all sets when policy cannot be refreshed for this long")
		resync         = flag.Duration("resync", 10*time.Second, "re-apply an unchanged policy this often (recovers from ruleset reloads)")
		once           = flag.Bool("once", false, "synchronize once and exit")
		dryRun         = flag.Bool("dry-run", false, "print the nft script instead of applying it")
		iface          = flag.String("interface", "wg0", "WireGuard interface whose peer table is verified against Guardian's bindings")
		callbackSource = flag.String("cwmp-cr-source", "", "opt-in ACS VIP for the separately installed IPv4 Connection Request profile")
		noVerify       = flag.Bool("skip-peer-verification", false, "UNSAFE: trust the database without checking the kernel peer table (dry runs only)")
	)
	flag.Parse()
	if *callbackSource != "" {
		if _, err := gatewayacl.RenderConnectionRequests(*table, *callbackSource, nil); err != nil {
			fmt.Fprintln(os.Stderr, "invalid cwmp-cr-source/table")
			os.Exit(2)
		}
	}
	if *interval <= 0 || *interval > 5*time.Second || *staleTTL <= 0 || *staleTTL > gatewayacl.MembershipTTL || *resync <= 0 || *resync > gatewayacl.MembershipTTL/3 {
		fmt.Fprintln(os.Stderr, "interval must be in (0,5s], stale-ttl in (0,30s], resync in (0,10s]")
		os.Exit(2)
	}
	if *noVerify && !*dryRun {
		fmt.Fprintln(os.Stderr, "skip-peer-verification requires dry-run")
		os.Exit(2)
	}

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
	var source gatewayacl.Source = st
	if *dryRun {
		source = readOnlySource{Source: st}
	}
	syncer := &gatewayacl.Syncer{
		Source: source, Applier: applier, Table: *table, ConnectionRequestSource: *callbackSource,
		ServiceIDs: domain.KnownServiceIDs(), StaleTTL: *staleTTL, ResyncInterval: *resync,
	}
	if !*noVerify {
		provider, err := wireguard.NewWGCtrlProvider(*iface)
		if err != nil {
			logger.Error("open WireGuard interface for peer verification", "interface", *iface, "error", err)
			os.Exit(1)
		}
		defer provider.Close()
		syncer.Observer = provider
	} else {
		logger.Warn("peer verification disabled: grants are not checked against the kernel peer table")
	}

	if *once {
		res, err := syncer.SyncOnce(ctx)
		if err != nil {
			logger.Error("sync", "error", err, "failed_closed", res.FailedClosed)
			os.Exit(1)
		}
		logRejections(logger, res)
		logger.Info("synced", "policy_revision", res.PolicyRevision, "targets", res.Targets, "changed", res.Changed)
		return
	}

	var lastErr, lastRejections string
	syncer.Run(ctx, *interval, func(res gatewayacl.SyncResult, err error) {
		if key := rejectionKey(res); key != lastRejections {
			lastRejections = key
			logRejections(logger, res)
		}
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

// rejectionKey summarizes the binding mismatches of one pass so that a
// persistent mismatch is logged once, not every interval.
func rejectionKey(res gatewayacl.SyncResult) string {
	key := fmt.Sprintf("%d/%d", res.UnexpectedPeers, res.AddressConflicts)
	for _, r := range res.Rejected {
		key += "|" + r.DeviceID + ":" + r.Reason
	}
	return key
}

// logRejections reports withheld grants. It logs device ids and reasons only:
// no keys, addresses or credentials.
func logRejections(logger *slog.Logger, res gatewayacl.SyncResult) {
	for _, r := range res.Rejected {
		logger.Warn("grant withheld: kernel peer does not match Guardian binding", "device_id", r.DeviceID, "reason", r.Reason)
	}
	if res.UnexpectedPeers > 0 {
		logger.Warn("kernel peers unknown to Guardian have no service access", "count", res.UnexpectedPeers)
	}
	if res.AddressConflicts > 0 {
		logger.Warn("peers denied: tunnel address claimed by more than one active peer", "count", res.AddressConflicts)
	}
}

// A dry run must never acknowledge a script it only printed.
type readOnlySource struct{ gatewayacl.Source }
