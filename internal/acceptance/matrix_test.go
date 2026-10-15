package acceptance

import "testing"

func goodManifest() Manifest {
	m := Manifest{Repos: map[string]string{}}
	for i, r := range RequiredRepos {
		m.Repos[r] = string(rune('a'+i)) + "0000000000000000000000000000000000000000"[1:]
	}
	return m
}

func fullReport(st Status) Report {
	r := Report{ManifestID: "m1", Manifest: goodManifest()}
	for _, sc := range Scenarios {
		r.Results = append(r.Results, Result{ID: sc.ID, Status: st, ManifestID: "m1", Evidence: "e", LeakScanClean: true})
	}
	return r
}

func TestScenarioCount(t *testing.T) {
	if len(Scenarios) != 18 {
		t.Fatalf("got %d", len(Scenarios))
	}
	for i, s := range Scenarios {
		if s.ID != i+1 {
			t.Fatalf("id order at %d", i)
		}
	}
}

func TestAllPassIsComplete(t *testing.T) {
	s := Evaluate(fullReport(StatusPass))
	if !s.Complete || s.Pass != 18 {
		t.Fatalf("%v %v", s, s.Problems)
	}
}

func TestWaivedIsNotPass(t *testing.T) {
	r := fullReport(StatusPass)
	r.Results[8] = Result{ID: 9, Status: StatusWaived, ManifestID: "m1", Reason: "no IPv6 in lab", LeakScanClean: true}
	s := Evaluate(r)
	if s.Complete || s.Waived != 1 || s.Pass != 17 {
		t.Fatalf("%v", s)
	}
}

func TestNonWaivableWaiverRejected(t *testing.T) {
	r := fullReport(StatusPass)
	r.Results[0] = Result{ID: 1, Status: StatusWaived, ManifestID: "m1", Reason: "x", LeakScanClean: true}
	if s := Evaluate(r); s.Complete || len(s.Problems) == 0 {
		t.Fatalf("%v", s)
	}
}

func TestMixedManifestAndLeaksAndMissing(t *testing.T) {
	r := fullReport(StatusPass)
	r.Results[1].ManifestID = "other"
	r.Results[2].LeakScanClean = false
	r.Results[3].Evidence = ""
	r.Results = r.Results[:17]
	s := Evaluate(r)
	if s.Complete || s.Pass != 14 || s.Fail != 2 || s.NotRun != 2 {
		t.Fatalf("%v %v", s, s.Problems)
	}
}

func TestDuplicateAndUnknown(t *testing.T) {
	r := fullReport(StatusPass)
	r.Results = append(r.Results, Result{ID: 3, Status: StatusPass, ManifestID: "m1"}, Result{ID: 99})
	if s := Evaluate(r); s.Complete {
		t.Fatal("complete")
	}
}

func TestManifestValidation(t *testing.T) {
	m := goodManifest()
	m.Repos["Admiral"] = "main"
	delete(m.Repos, "SunkarDAV")
	if err := m.Validate(); err == nil {
		t.Fatal("want error")
	}
	if err := goodManifest().Validate(); err != nil {
		t.Fatal(err)
	}
}
