// Package gatewayacl projects Guardian's service policy onto nftables sets of
// the service gateway. It only ever replaces the contents of pre-declared
// sets inside one atomic nft transaction; the ruleset itself is static and
// shipped with the deployment.
package gatewayacl

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/1day0fmylife/Guardian/internal/store"
)

var (
	tableNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,31}$`)
	serviceIDPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
)

// SetName returns the nftables set that holds the peer addresses allowed to
// reach a service, e.g. "sunkarcwmp-acs" -> "svc_sunkarcwmp_acs_v4".
func SetName(serviceID string) string {
	return "svc_" + strings.ReplaceAll(serviceID, "-", "_") + "_v4"
}

// Render produces one nft script that atomically replaces the contents of the
// set of every given service. Services without allowed peers get an empty
// set, so a revoked grant is removed rather than left behind. Only IPv4
// peers are projected; IPv6 addresses are never allowed.
func Render(table string, serviceIDs []string, targets []store.ServiceAccessTarget) (string, error) {
	if !tableNamePattern.MatchString(table) {
		return "", fmt.Errorf("invalid nftables table name")
	}
	perService := map[string][]netip.Addr{}
	known := map[string]bool{}
	for _, id := range serviceIDs {
		known[id] = true
	}
	for _, target := range targets {
		if !target.Address.Is4() {
			continue
		}
		for _, id := range target.ServiceIDs {
			if known[id] {
				perService[id] = append(perService[id], target.Address)
			}
		}
	}

	ids := append([]string(nil), serviceIDs...)
	sort.Strings(ids)
	var b strings.Builder
	for _, id := range ids {
		if !serviceIDPattern.MatchString(id) {
			return "", fmt.Errorf("invalid service id %q", id)
		}
		set := SetName(id)
		fmt.Fprintf(&b, "flush set inet %s %s\n", table, set)
		addrs := perService[id]
		sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
		var elems []string
		for i, addr := range addrs {
			if i > 0 && addrs[i-1] == addr {
				continue
			}
			elems = append(elems, addr.String())
		}
		if len(elems) > 0 {
			fmt.Fprintf(&b, "add element inet %s %s { %s }\n", table, set, strings.Join(elems, ", "))
		}
	}
	return b.String(), nil
}

// Applier executes an nft script atomically.
type Applier interface {
	Apply(ctx context.Context, script string) error
}

// NftApplier runs `nft -f -`, which applies the whole script as a single
// transaction: either every set changes or none does.
type NftApplier struct{ Binary string }

func (a NftApplier) Apply(ctx context.Context, script string) error {
	bin := a.Binary
	if bin == "" {
		bin = "nft"
	}
	cmd := exec.CommandContext(ctx, bin, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stderr = &out
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft apply: %w: %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}

// Source provides the current policy snapshot.
type Source interface {
	ServiceAccessSnapshot(ctx context.Context) (store.ServiceAccessSnapshot, error)
}

// Syncer keeps the gateway sets equal to Guardian's policy. It fails closed:
// when the policy cannot be read or applied for longer than StaleTTL, all
// service sets are flushed so that stale permissions do not outlive an outage
// of the control plane.
type Syncer struct {
	Source     Source
	Applier    Applier
	Table      string
	ServiceIDs []string
	StaleTTL   time.Duration
	// ResyncInterval forces a re-apply of an unchanged policy so that sets
	// are rebuilt after the gateway ruleset was reloaded or the host
	// rebooted. Zero disables forced re-apply.
	ResyncInterval time.Duration
	Now            func() time.Time

	mu            sync.Mutex
	lastSuccess   time.Time
	lastAppliedAt time.Time
	lastApplied   string
	lastRev       int64
}

// SyncResult reports what one pass did.
type SyncResult struct {
	PolicyRevision int64
	Targets        int
	Changed        bool
	FailedClosed   bool
}

func (s *Syncer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// SyncOnce performs a single reconciliation pass.
func (s *Syncer) SyncOnce(ctx context.Context) (SyncResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	snap, err := s.Source.ServiceAccessSnapshot(ctx)
	if err != nil {
		return s.failClosed(ctx, fmt.Errorf("read policy: %w", err))
	}
	script, err := Render(s.Table, s.ServiceIDs, snap.Targets)
	if err != nil {
		return s.failClosed(ctx, err)
	}
	result := SyncResult{PolicyRevision: snap.PolicyRevision, Targets: len(snap.Targets)}
	changed := script != s.lastApplied
	if changed || (s.ResyncInterval > 0 && s.now().Sub(s.lastAppliedAt) >= s.ResyncInterval) {
		if err := s.Applier.Apply(ctx, script); err != nil {
			return s.failClosed(ctx, err)
		}
		s.lastApplied = script
		s.lastAppliedAt = s.now()
		result.Changed = changed
	}
	s.lastSuccess = s.now()
	s.lastRev = snap.PolicyRevision
	return result, nil
}

func (s *Syncer) failClosed(ctx context.Context, cause error) (SyncResult, error) {
	if !s.lastSuccess.IsZero() && s.now().Sub(s.lastSuccess) < s.StaleTTL {
		return SyncResult{PolicyRevision: s.lastRev}, cause
	}
	// Never synced successfully or stale for too long: deny everything.
	empty, err := Render(s.Table, s.ServiceIDs, nil)
	if err != nil {
		return SyncResult{FailedClosed: true}, fmt.Errorf("%v; render empty policy: %w", cause, err)
	}
	if empty != s.lastApplied {
		if err := s.Applier.Apply(ctx, empty); err != nil {
			return SyncResult{FailedClosed: true}, fmt.Errorf("%v; flush sets: %w", cause, err)
		}
		s.lastApplied = empty
		s.lastAppliedAt = s.now()
	}
	return SyncResult{FailedClosed: true}, cause
}

// Run synchronizes until the context ends. onResult receives every pass.
func (s *Syncer) Run(ctx context.Context, interval time.Duration, onResult func(SyncResult, error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		res, err := s.SyncOnce(ctx)
		if onResult != nil {
			onResult(res, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
