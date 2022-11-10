package abnf_gen

import (
	"fmt"
	"io"

	"github.com/ghettovoice/abnf"
)

// ParserGenerator generates ABNF rules as operator functions or operator factories in memory.
type ParserGenerator struct {
	External map[string]ExternalRule

	rulesParser

	oprts    map[string]abnf.Operator
	factrs   map[string]OperatorFactory
	ruleName string
}

// ReadFrom reads and parses ABNF grammar from src.
func (g *ParserGenerator) ReadFrom(src io.Reader) (int64, error) {
	if len(g.factrs) > 0 {
		for n := range g.factrs {
			delete(g.factrs, n)
		}
	}
	if len(g.oprts) > 0 {
		for n := range g.oprts {
			delete(g.oprts, n)
		}
	}
	return g.rulesParser.ReadFrom(src)
}

// Factories returns a map of ABNF rules as operator factories.
func (g *ParserGenerator) Factories() map[string]OperatorFactory {
	if len(g.factrs) == 0 {
		if g.factrs == nil {
			g.factrs = make(map[string]OperatorFactory, len(g.rules))
		}
		for n, r := range g.rules {
			g.factrs[n] = r.buildFactr(g)
		}
	}
	return g.factrs
}

// Operators returns a map of ABNF rules as operator functions.
func (g *ParserGenerator) Operators() map[string]abnf.Operator {
	if len(g.oprts) == 0 {
		if g.oprts == nil {
			g.oprts = make(map[string]abnf.Operator, len(g.rules))
		}
		if len(g.factrs) > 0 {
			for n, f := range g.factrs {
				g.oprts[n] = f()
			}
		} else {
			for n, r := range g.rules {
				g.oprts[n] = r.buildOprt(g)
			}
		}
	}
	return g.oprts
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
	buildFactr(g *ParserGenerator) OperatorFactory
}

func (r rule) buildOprt(g *ParserGenerator) abnf.Operator {
	g.ruleName = r.name

	return r.oprt.buildOprt(g)
}

func (r rule) buildFactr(g *ParserGenerator) OperatorFactory {
	factr := r.oprt.buildFactr(g)
	return func() abnf.Operator {
		if _, ok := g.oprts[r.name]; !ok {
			if g.oprts == nil {
				g.oprts = make(map[string]abnf.Operator)
			}
			g.ruleName = r.name
			g.oprts[r.name] = factr()
		}
		return g.oprts[r.name]
	}
}

func (op altOperator) buildOprt(g *ParserGenerator) abnf.Operator {
	key := g.oprtKey(op.key())
	oprts := make([]abnf.Operator, 0, len(op.oprts))
	for _, op := range op.oprts {
		oprts = append(oprts, op.buildOprt(g))
	}
	return abnf.Alt(key, oprts...)
}

func (op altOperator) buildFactr(g *ParserGenerator) OperatorFactory {
	return func() abnf.Operator { return op.buildOprt(g) }
}

func (op concatOperator) buildOprt(g *ParserGenerator) abnf.Operator {
	key := g.oprtKey(op.key())
	oprts := make([]abnf.Operator, 0, len(op.oprts))
	for _, op := range op.oprts {
		oprts = append(oprts, op.buildOprt(g))
	}
	return abnf.Concat(key, oprts...)
}

func (op concatOperator) buildFactr(g *ParserGenerator) OperatorFactory {
	return func() abnf.Operator { return op.buildOprt(g) }
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

func (op repeatOperator) buildFactr(g *ParserGenerator) OperatorFactory {
	return func() abnf.Operator { return op.buildOprt(g) }
}

func (op ruleNameOperator) buildOprt(g *ParserGenerator) abnf.Operator {
	if extRule, ok := g.External[op.key()]; ok {
		if extRule.IsOperator {
			if extRule.Operator == nil {
				panic(fmt.Errorf("invalid external ABNF rule '%s' found: 'Operator' field is empty", op.key()))
			}
			return extRule.Operator
		}

		if extRule.Factory == nil {
			panic(fmt.Errorf("invalid external ABNF rule '%s' found: 'Factory' field is empty", op.key()))
		}
		return extRule.Factory()
	}

	return func(s []byte, ns abnf.Nodes) abnf.Nodes {
		var (
			oprt abnf.Operator
			ok   bool
		)
		if oprt, ok = g.oprts[op.key()]; !ok {
			var factr OperatorFactory
			if factr, ok = g.factrs[op.key()]; ok {
				oprt = factr()
			}
		}
		if !ok {
			panic(fmt.Errorf("unknown ABNF rule '%s'", op.key()))
		}
		return oprt(s, ns)
	}
}

func (op ruleNameOperator) buildFactr(g *ParserGenerator) OperatorFactory {
	return func() abnf.Operator { return op.buildOprt(g) }
}

func (op optionOperator) buildOprt(g *ParserGenerator) abnf.Operator {
	return abnf.Optional(g.oprtKey(op.key()), op.oprt.buildOprt(g))
}

func (op optionOperator) buildFactr(g *ParserGenerator) OperatorFactory {
	return func() abnf.Operator { return op.buildOprt(g) }
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

func (op charValOperator) buildFactr(g *ParserGenerator) OperatorFactory {
	return func() abnf.Operator { return op.buildOprt(g) }
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

func (op numValOperator) buildFactr(g *ParserGenerator) OperatorFactory {
	return func() abnf.Operator { return op.buildOprt(g) }
}
