package abnf

import (
	"errors"
	"fmt"
)

const (
	// ErrNotMatched returned by operators if input doesn't match
	ErrNotMatched sentinelError = "not matched"
)

type sentinelError string

func (e sentinelError) Error() string { return string(e) }

func newOpError(op string, pos uint, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("operator %q failed at position %d: %w", op, pos, err) //errtrace:skip
}

func joinErrs(errs ...error) error {
	err := errors.Join(errs...)
	if err == nil {
		return nil
	}
	return fmt.Errorf("\n%w", err) //errtrace:skip
}
