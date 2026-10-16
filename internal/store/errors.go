package store

import (
	"errors"
	"fmt"
)

var ErrInvalid = errors.New("invalid input")

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// ErrLastSuperadmin rejects a mutation that would leave no active superadmin.
// It wraps ErrConflict so generic conflict handling still applies.
var ErrLastSuperadmin = fmt.Errorf("%w: last active superadmin", ErrConflict)
