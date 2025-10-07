// Package abnf_gen implements parser and code generation from ABNF grammar.
package abnf_gen

import (
	"github.com/ghettovoice/abnf"
)

// ExternalRule defines an external ABNF rule.
//
// [ParserGenerator] uses Operator field.
// [CodeGenerator] uses PackagePath and PackageName fields.
type ExternalRule struct {
	Operator    abnf.Operator
	PackagePath string
	PackageName string
}
