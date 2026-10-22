package store

import (
	"context"
	"encoding/json"
	"testing"
)

// Empty collections must encode as [] rather than null; the WebUI maps over them directly.
func TestEmptyListsEncodeAsArrays(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	enrollments, _, err := s.ListEnrollments(ctx, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	commands, _, err := s.ListAllDeviceCommands(ctx, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := s.ListVPNProfiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pools, err := s.ListAddressPools(ctx)
	if err != nil {
		t.Fatal(err)
	}

	for name, value := range map[string]any{"enrollments": enrollments, "commands": commands, "profiles": profiles, "pools": pools} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if string(encoded) == "null" {
			t.Errorf("%s encoded as null, want []", name)
		}
	}
}
