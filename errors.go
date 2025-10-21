package abnf

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

const (
	// ErrNotMatched returned by operators if input doesn't match
	ErrNotMatched sentinelError = "not matched"
)

type sentinelError string

func (e sentinelError) Error() string { return string(e) }

type operError struct {
	op  string
	pos uint
	err error
}

func (e operError) Unwrap() error { return e.err }

func (e operError) Error() string {
	var sb strings.Builder
	e.writeError(&sb, 0)
	return sb.String()
}

func (e *operError) writeError(sb *strings.Builder, depth int) {
	fmt.Fprintf(sb, "operator %q failed at position %d: ", e.op, e.pos)

	var merr multiError
	if errors.As(e.err, &merr) {
		merr.writeError(sb, depth)
	} else {
		sb.WriteString(e.err.Error())
	}
}

type multiError []error

func (e multiError) Unwrap() []error { return e }

func (e multiError) Error() string {
	var sb strings.Builder
	e.writeError(&sb, 0)
	return sb.String()
}

func (e multiError) writeError(sb *strings.Builder, depth int) {
	sb.WriteString("following errors are occurred:\n")

	for _, err := range e {
		var (
			merr multiError
			oerr *operError
		)
		if errors.As(err, &oerr) {
			sb.WriteString(strings.Repeat("  ", depth+1) + "- ")
			oerr.writeError(sb, depth+1)
			sb.WriteString("\n")
		} else if errors.As(err, &merr) {
			merr.writeError(sb, depth+1)
		} else {
			sb.WriteString(strings.Repeat("  ", depth+1) + "- " + err.Error() + "\n")
		}
	}
}

const multiErrCap = 10

var multiErrPool = &sync.Pool{
	New: func() any {
		errs := multiError(make([]error, 0, multiErrCap))
		return &errs
	},
}

func newMultiErr(c uint) multiError {
	var err multiError
	if c <= multiErrCap {
		errPtr := multiErrPool.Get().(*multiError)
		err = *errPtr
	} else {
		err = make(multiError, 0, c)
	}
	return err
}

func (e *multiError) clear() {
	if e == nil {
		return
	}

	clear(*e)
	*e = (*e)[:0]
}

func (e *multiError) free() {
	if e == nil || cap(*e) > 10*multiErrCap {
		return
	}

	e.clear()
	multiErrPool.Put(e)
}
