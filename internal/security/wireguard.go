package security

import (
	"encoding/base64"
	"errors"
)

var ErrInvalidWireGuardPublicKey = errors.New("invalid WireGuard public key")

func ValidateWireGuardPublicKey(value string) error {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 {
		return ErrInvalidWireGuardPublicKey
	}

	var nonZero byte
	for _, b := range raw {
		nonZero |= b
	}
	if nonZero == 0 {
		return ErrInvalidWireGuardPublicKey
	}
	return nil
}
