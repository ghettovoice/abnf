// Package abnf provides basic ABNF operators (RFC 5234, RFC 7405).
//
// Core ABNF rules implementation can be found in [github.com/ghettovoice/abnf/pkg/abnf_core],
// ABNF definition rules are in [github.com/ghettovoice/abnf/pkg/abnf_def],
// code and parser generators are in [github.com/ghettovoice/abnf/pkg/abnf_gen].
package abnf

// VERSION is the package version
const VERSION = "v0.4.1"

// Rule is a function that implements an ABNF rule.
// Rule always parses input starting from the position 0.
type Rule = func(in []byte, ns Nodes) (Nodes, error)
