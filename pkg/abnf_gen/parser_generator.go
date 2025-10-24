package abnf_gen

import (
	"fmt"
	"io"

	"braces.dev/errtrace"
	"github.com/ghettovoice/abnf"
)

// ParserGenerator generates ABNF rules as operator functions or operator factories in memory.
type ParserGenerator struct {
	External map[string]ExternalRule

	rulesParser

	oprts    map[string]abnf.Operator
	rules    map[string]abnf.Rule
	ruleName string
}

// ReadFrom reads and parses ABNF grammar from src.
func (g *ParserGenerator) ReadFrom(src io.Reader) (int64, error) {
	clear(g.oprts)
	return errtrace.Wrap2(g.rulesParser.ReadFrom(src))
}

// Operators returns a map of ABNF rules as operator functions.
func (g *ParserGenerator) Operators() map[string]abnf.Operator {
	if len(g.oprts) == 0 {
		if g.oprts == nil {
			g.oprts = make(map[string]abnf.Operator, len(g.rulesParser.rules))
		}
		for n, r := range g.rulesParser.rules {
			g.oprts[n] = r.buildOprt(g)
		}
	}
	return g.oprts
}

// Rules returns a map of ABNF rules as functions that start parsing from position 0.
func (g *ParserGenerator) Rules() map[string]abnf.Rule {
	if len(g.rules) == 0 {
		oprts := g.Operators()
		if g.rules == nil {
			g.rules = make(map[string]abnf.Rule, len(oprts))
		}
		for n, op := range oprts {
			g.rules[n] = func(in []byte, ns *abnf.Nodes) error {
				return op(in, 0, ns) //errtrace:skip
			}
		}
	}
	return g.rules
}

func (g *ParserGenerator) oprtKey(key string) string {
	if g.ruleName != "" {
		key = g.ruleName
		g.ruleName = ""
	}
	return key
}

type operatorBuilder interface {
	buildOprt(g *ParserGenerator) abnf.Operator
}

func (r rule) buildOprt(g *ParserGenerator) abnf.Operator {
	g.ruleName = r.name

	return r.oprt.buildOprt(g)
}

func (op altOperator) buildOprt(g *ParserGenerator) abnf.Operator {
	key := g.oprtKey(op.key())
	oprts := make([]abnf.Operator, 0, len(op.oprts))
	for _, op := range op.oprts {
		oprts = append(oprts, op.buildOprt(g))
	}
	return abnf.Alt(key, oprts[0], oprts[1:]...)
}

func (op concatOperator) buildOprt(g *ParserGenerator) abnf.Operator {
	key := g.oprtKey(op.key())
	oprts := make([]abnf.Operator, 0, len(op.oprts))
	for _, op := range op.oprts {
		oprts = append(oprts, op.buildOprt(g))
	}
	return abnf.Concat(key, oprts[0], oprts[1:]...)
}

func (op repeatOperator) buildOprt(g *ParserGenerator) abnf.Operator {
	key := g.oprtKey(op.key())

	if op.max == 0 {
		if op.min == 0 {
			return abnf.Repeat0Inf(key, op.oprt.buildOprt(g))
		}
		if op.min == 1 {
			return abnf.Repeat1Inf(key, op.oprt.buildOprt(g))
		}
	}

	if op.min == op.max {
		return abnf.RepeatN(key, op.min, op.oprt.buildOprt(g))
	}

	return abnf.Repeat(key, op.min, op.max, op.oprt.buildOprt(g))
}

func (op ruleNameOperator) buildOprt(g *ParserGenerator) abnf.Operator {
	if extRule, ok := g.External[op.key()]; ok {
		if extRule.Operator == nil {
			panic(fmt.Errorf("invalid external ABNF rule '%s' found: 'Operator' field is empty", op.key()))
		}
		return extRule.Operator
	}

	return func(in []byte, pos uint, ns *abnf.Nodes) error {
		var (
			oprt abnf.Operator
			ok   bool
		)
		if oprt, ok = g.oprts[op.key()]; !ok {
			panic(fmt.Errorf("unknown ABNF rule '%s'", op.key()))
		}
		return oprt(in, pos, ns) //errtrace:skip
	}
}

func (op optionOperator) buildOprt(g *ParserGenerator) abnf.Operator {
	return abnf.Optional(g.oprtKey(op.key()), op.oprt.buildOprt(g))
}

func (op charValOperator) buildOprt(g *ParserGenerator) abnf.Operator {
	var oprtFunc func(string, []byte) abnf.Operator
	if op.cs {
		oprtFunc = abnf.LiteralCS
	} else {
		oprtFunc = abnf.Literal
	}
	return oprtFunc(g.oprtKey(op.key()), []byte(op.val))
}

func (op numValOperator) buildOprt(g *ParserGenerator) abnf.Operator {
	vals := op.byteVals()

	if op.isRange {
		return abnf.Range(op.key(), vals[0], vals[1])
	}

	buf := make([]byte, 0, len(vals))
	for _, v := range vals {
		buf = append(buf, v...)
	}
	return abnf.Literal(g.oprtKey(op.key()), buf)
}
