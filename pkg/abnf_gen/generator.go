// Package abnf_gen implements parser and code generation from ABNF grammar.
package abnf_gen

import (
	"github.com/ghettovoice/abnf"
)

// ExternalRule defines an external ABNF rule.
//
// [ParserGenerator] uses Operator and Factory fields.
// [CodeGenerator] uses PackagePath and PackageName fields.
// IsOperator field is used by both generators.
type ExternalRule struct {
	IsOperator bool

	Operator abnf.Operator
	Factory  OperatorFactory

	PackagePath string
	PackageName string
}

type OperatorFactory func() abnf.Operator
