package security

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestValidateWireGuardPublicKey(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	if err := ValidateWireGuardPublicKey(valid); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}

	zero := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := ValidateWireGuardPublicKey(zero); err == nil {
		t.Fatal("zero key should be rejected")
	}

	if err := ValidateWireGuardPublicKey("not-a-wireguard-key"); err == nil {
		t.Fatal("malformed key should be rejected")
	}
}
