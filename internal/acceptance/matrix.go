// Package acceptance evaluates the X-01 pinned-manifest and X-02 negative
// matrix evidence. It never runs a topology itself: orchestrators (Admiral
// deploy/secured, ArlanPhone QEMU) emit results and this package decides
// whether they amount to a valid, complete 18/18 report.
package acceptance

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Status string

const (
	StatusPass    Status = "PASS"
	StatusFail    Status = "FAIL"
	StatusBlocked Status = "BLOCKED"
	StatusNotRun  Status = "NOT_RUN"
	StatusWaived  Status = "WAIVED"
)

// Scenario is one X-02 negative case.
type Scenario struct {
	ID       int
	Name     string
	Expected string
	// Waivable cases may be WAIVED with a reason; a waiver is never a PASS.
	Waivable bool
}

// Scenarios is the 18-case X-02 matrix from the ecosystem plan.
var Scenarios = []Scenario{
	{1, "no-enrollment", "no access to internal services", false},
	{2, "dav-grant-absent", "DAV blocked despite successful WG", false},
	{3, "dav-invalid-account", "DAV 401/403, no data", false},
	{4, "dav-cross-calendar", "cross-user data not disclosed", false},
	{5, "acs-grant-absent", "CWMP never reaches ACS", false},
	{6, "acs-revoked-credential", "ACS rejects, Admiral shows auth failure", false},
	{7, "vpn-drop-dav-upload", "fail closed, offline cache survives, safe retry", false},
	{8, "vpn-drop-ota-download", "no unverified install, resume/retry", false},
	{9, "dns-redirect-ipv6", "fail closed; no direct fallback", true},
	{10, "spoofed-identity", "gateway/ACS reject", false},
	{11, "api-caddy-wgkey-restart", "no escalation, convergent policy", false},
	{12, "revoke-mid-session", "new traffic denied; deterministic drain", false},
	{13, "acs-postgres-outage", "bounded retries (503/Retry-After), no false revoke, no leaks", false},
	{14, "admiral-nbi-unavailable", "no duplicate inventory; idempotent recovery", false},
	{15, "cross-device-grants", "no cross-device access", false},
	{16, "independent-sip-rtp", "call survives Guardian disconnect", false},
	{17, "first-boot-no-time", "supported bootstrap or safe denial, no TLS bypass", false},
	{18, "restart-no-leak", "no secret leakage or phantom managed status", false},
}

// Repositories that must be pinned in the manifest.
var RequiredRepos = []string{"Guardian", "Admiral", "SunkarCWMP", "SunkarDAV", "ArlanPhone"}

var shaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

type Manifest struct {
	// Repos maps repository name to the exact 40-hex commit SHA under test.
	Repos map[string]string `json:"repos"`
	// Releases optionally records component release/binary identifiers.
	Releases map[string]string `json:"releases,omitempty"`
}

func (m Manifest) Validate() error {
	var problems []string
	for _, r := range RequiredRepos {
		sha, ok := m.Repos[r]
		switch {
		case !ok:
			problems = append(problems, r+": missing")
		case !shaRe.MatchString(sha):
			problems = append(problems, r+": not an exact 40-hex SHA")
		}
	}
	if len(problems) > 0 {
		return errors.New("manifest invalid: " + strings.Join(problems, "; "))
	}
	return nil
}

type Result struct {
	ID     int    `json:"id"`
	Status Status `json:"status"`
	// Manifest is the manifest digest/identity this result ran against; must
	// equal the report manifest ID so mixed-revision runs are rejected.
	ManifestID string `json:"manifestId"`
	Evidence   string `json:"evidence,omitempty"`
	Reason     string `json:"reason,omitempty"`
	// Observed secrets-scan outcome for the captured logs of this case.
	LeakScanClean bool `json:"leakScanClean"`
}

type Report struct {
	ManifestID string    `json:"manifestId"`
	Manifest   Manifest  `json:"manifest"`
	Results    []Result  `json:"results"`
	StartedAt  time.Time `json:"startedAt"`
}

type Summary struct {
	Pass, Fail, Blocked, NotRun, Waived int
	Complete                            bool // exactly 18/18 PASS, no waivers
	Problems                            []string
}

func (s Summary) String() string {
	return fmt.Sprintf("%d/%d PASS (fail=%d blocked=%d not_run=%d waived=%d)",
		s.Pass, len(Scenarios), s.Fail, s.Blocked, s.NotRun, s.Waived)
}

// Evaluate validates the report and tallies it. Missing scenarios count as
// NOT_RUN; duplicates, unknown IDs, mixed manifests, unexplained waivers and
// dirty leak scans are problems and prevent Complete.
func Evaluate(r Report) Summary {
	var s Summary
	if err := r.Manifest.Validate(); err != nil {
		s.Problems = append(s.Problems, err.Error())
	}
	if r.ManifestID == "" {
		s.Problems = append(s.Problems, "report manifestId empty")
	}
	byID := map[int]Result{}
	for _, res := range r.Results {
		if res.ID < 1 || res.ID > len(Scenarios) {
			s.Problems = append(s.Problems, fmt.Sprintf("unknown scenario %d", res.ID))
			continue
		}
		if _, dup := byID[res.ID]; dup {
			s.Problems = append(s.Problems, fmt.Sprintf("scenario %d duplicated", res.ID))
			continue
		}
		byID[res.ID] = res
	}
	for _, sc := range Scenarios {
		res, ok := byID[sc.ID]
		if !ok {
			s.NotRun++
			continue
		}
		if subtle.ConstantTimeCompare([]byte(res.ManifestID), []byte(r.ManifestID)) != 1 {
			s.Problems = append(s.Problems, fmt.Sprintf("scenario %d ran on a different manifest", sc.ID))
			s.Fail++
			continue
		}
		switch res.Status {
		case StatusPass:
			if res.Evidence == "" {
				s.Problems = append(s.Problems, fmt.Sprintf("scenario %d PASS without evidence", sc.ID))
				s.NotRun++
			} else if !res.LeakScanClean {
				s.Problems = append(s.Problems, fmt.Sprintf("scenario %d leak scan not clean", sc.ID))
				s.Fail++
			} else {
				s.Pass++
			}
		case StatusFail:
			s.Fail++
		case StatusBlocked:
			s.Blocked++
		case StatusNotRun:
			s.NotRun++
		case StatusWaived:
			if !sc.Waivable || res.Reason == "" {
				s.Problems = append(s.Problems, fmt.Sprintf("scenario %d waiver not allowed or unexplained", sc.ID))
				s.Fail++
			} else {
				s.Waived++
			}
		default:
			s.Problems = append(s.Problems, fmt.Sprintf("scenario %d unknown status %q", sc.ID, res.Status))
			s.Fail++
		}
	}
	sort.Strings(s.Problems)
	s.Complete = s.Pass == len(Scenarios) && len(s.Problems) == 0
	return s
}
