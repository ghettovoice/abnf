package abnf

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	// ErrNotMatched returned by operators if input doesn't match
	ErrNotMatched sentinelError = "not matched"
)

var detailErrs atomic.Bool

// EnableDetailedErrors enables detailed operator errors.
func EnableDetailedErrors() { detailErrs.Store(true) }

// DisableDetailedErrors disables detailed operator errors.
func DisableDetailedErrors() { detailErrs.Store(false) }

type sentinelError string

func (e sentinelError) Error() string { return string(e) }

type operError struct {
	op  string
	pos uint
	err error
}

func (e operError) Unwrap() error { return e.err }

func (e operError) Error() string {
	sb := bytes.NewBuffer(make([]byte, 0, 128))
	e.writeError(sb, 0)
	return sb.String()
}

func (e operError) writeError(sb *bytes.Buffer, depth int) {
	fmt.Fprintf(sb, "operator %q failed at position %d:", e.op, e.pos)

	var merr *multiError
	if errors.As(e.err, &merr) {
		merr.writeError(sb, depth)
	} else {
		sb.WriteString(" ")
		sb.WriteString(e.err.Error())
	}
}

type multiError []error

func (e *multiError) Unwrap() []error {
	if e == nil {
		return nil
	}
	return *e
}

func (e *multiError) Error() string {
	if e == nil {
		return "<nil>"
	}

	sb := bytes.NewBuffer(make([]byte, 0, 128))
	e.writeError(sb, 0)
	return sb.String()
}

func (e *multiError) writeError(sb *bytes.Buffer, depth int) {
	sb.WriteString("\n")

	for i, err := range *e {
		if i > 0 {
			sb.WriteString("\n")
		}

		var (
			me *multiError
			oe operError
		)
		if errors.As(err, &oe) {
			sb.WriteString(strings.Repeat("  ", depth+1))
			sb.WriteString("- ")
			oe.writeError(sb, depth+1)
		} else if errors.As(err, &me) {
			me.writeError(sb, depth+1)
		} else {
			sb.WriteString(strings.Repeat("  ", depth+1))
			sb.WriteString("- ")
			sb.WriteString(err.Error())
		}
	}
}

const multiErrCap = 3

var multiErrPool = &sync.Pool{
	New: func() any {
		me := make(multiError, 0, multiErrCap)
		return &me
	},
}

func newMultiErr(c uint) *multiError {
	var err *multiError
	if c <= multiErrCap {
		err = multiErrPool.Get().(*multiError)
	} else {
		me := make(multiError, 0, c)
		err = &me
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

func wrapOperError(op string, pos uint, err error) error {
	if err == nil {
		return nil
	}

	if !detailErrs.Load() {
		if errors.Is(err, ErrNotMatched) {
			if me, ok := err.(*multiError); ok {
				me.free()
			}
			if oe, ok := err.(operError); ok {
				if me, ok := oe.err.(*multiError); ok {
					me.free()
				}
			}
			return ErrNotMatched
		}
		return err
	}

	var oerr operError
	if errors.As(err, &oerr) && oerr.op == op && oerr.pos == pos {
		return err
	}

	return operError{op: op, pos: pos, err: err}
}

func wrapNotMatched(op string, pos uint) error {
	return wrapOperError(op, pos, ErrNotMatched)
}
