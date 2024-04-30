package abnf_gen

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"math/bits"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/ghettovoice/abnf"
	"github.com/ghettovoice/abnf/pkg/abnf_def"
)

type rulesParser struct {
	rules map[string]rule
}

func (p *rulesParser) ReadFrom(src io.Reader) (int64, error) {
	s, err := io.ReadAll(src)
	if err != nil {
		return 0, fmt.Errorf("read source: %w", err)
	}

	if !bytes.HasSuffix(s, []byte("\n")) {
		s = append(s, '\n')
	}

	rules, err := parseRules(s)
	if err != nil {
		return int64(len(s)), fmt.Errorf("parse source: %w", err)
	}

	if p.rules == nil {
		p.rules = rules
	} else {
		for name, newRule := range rules {
			if foundRule, ok := p.rules[name]; ok {
				p.rules[name] = mergeRules(name, foundRule, newRule)
			} else {
				p.rules[name] = newRule
			}
		}
	}

	return int64(len(s)), nil
}

type rule struct {
	name   string
	oprt   operator
	extend bool
}

func (r rule) pubName() string {
	return fmtPubRuleName(r.name)
}

func (r rule) privName() string {
	return fmtPrivRuleName(r.name)
}

func fmtPubRuleName(n string) string {
	words := strings.Split(n, "-")
	var nn string
	for _, w := range words {
		for _, c := range w {
			nn += string(unicode.ToUpper(c)) + w[1:]
			break
		}
	}
	return nn
}

func fmtPrivRuleName(n string) string {
	words := strings.Split(n, "-")
	var nn string
	for i, w := range words {
		if i == 0 {
			nn += strings.ToLower(w)
		} else {
			for _, c := range w {
				nn += string(unicode.ToUpper(c)) + w[1:]
				break
			}
		}
	}
	return nn
}

type operator interface {
	key() string

	operatorBuilder
	statementBuilder
}

type altOperator struct {
	k     string
	oprts []operator
}

func (op altOperator) key() string { return op.k }

type concatOperator struct {
	k     string
	oprts []operator
}

func (op concatOperator) key() string { return op.k }

type repeatOperator struct {
	k        string
	oprt     operator
	min, max uint
}

func (op repeatOperator) key() string { return op.k }

type ruleNameOperator struct {
	k string
}

func (op ruleNameOperator) key() string { return op.k }

type optionOperator struct {
	k    string
	oprt operator
}

func (op optionOperator) key() string { return op.k }

type charValOperator struct {
	val string
	cs  bool
}

func (op charValOperator) key() string { return fmt.Sprintf("%q", op.val) }

type numValOperator struct {
	k       string
	typ     numType
	vals    []string
	isRange bool
}

func (op numValOperator) key() string { return op.k }

func (op numValOperator) byteVals() [][]byte {
	out := make([][]byte, len(op.vals))
	switch op.typ {
	case binNum:
		for i, v := range op.vals {
			iv, _ := strconv.ParseUint(v, 2, 8)
			out[i] = []byte{byte(iv)}
		}
	case decNum:
		for i, v := range op.vals {
			iv, _ := strconv.ParseUint(v, 10, 64)
			out[i] = int2bytes(iv)
		}
	case hexNum:
		for i, v := range op.vals {
			iv, _ := strconv.ParseUint(v, 16, 64)
			out[i] = int2bytes(iv)
		}
	}
	return out
}

func int2bytes(in uint64) []byte {
	l := int(math.Ceil(float64(bits.Len64(in)) / 8))
	if l == 0 {
		l = 1
	}
	out := make([]byte, l)
	for i := range out {
		out[i] = byte(in >> (i * 8))
	}
	return out
}

type numType uint

const (
	binNum numType = iota + 1
	decNum
	hexNum
)

func parseRules(s []byte) (map[string]rule, error) {
	n := abnf_def.Rulelist(s, nil).Best()
	if n.Len() < len(s) {
		return nil, fmt.Errorf("source isn't fully consumed, source length %d != best match length %d", n.Len(), len(s))
	}

	return parseRuleslistNode(n), nil
}

func parseRuleslistNode(n abnf.Node) map[string]rule {
	rules := make(map[string]rule)
	for _, n := range n.Children {
		if n, ok := n.GetNode("rule"); ok {
			newRule := parseRuleNode(n)
			if foundRule, ok := rules[newRule.name]; ok && newRule.extend {
				rules[newRule.name] = mergeRules(newRule.name, foundRule, newRule)
			} else {
				rules[newRule.name] = newRule
			}
		}
	}
	return rules
}

func mergeRules(n string, r1, r2 rule) rule {
	op := altOperator{
		k: r1.oprt.key(),
	}
	switch o := r1.oprt.(type) {
	case altOperator:
		op.oprts = o.oprts
	default:
		op.oprts = []operator{o}
	}

	op.k += " / " + r2.oprt.key()
	switch o := r2.oprt.(type) {
	case altOperator:
		op.oprts = append(op.oprts, o.oprts...)
	default:
		op.oprts = append(op.oprts, o)
	}

	return rule{
		name: n,
		oprt: op,
	}
}

func parseRuleNode(n abnf.Node) rule {
	return rule{
		name:   mustGetNode(n, "rulename").String(),
		oprt:   parseAlternationNode(mustGetNode(n, "alternation")),
		extend: n.Contains("=/"),
	}
}

func parseAlternationNode(n abnf.Node) operator {
	ops := []operator{
		parseConcatenationNode(mustGetNode(n, "concatenation")),
	}
	// traverse '*(*c-wsp "/" *c-wsp concatenation)' part
	for _, n := range n.Children[1].Children {
		if n, ok := n.GetNode("concatenation"); ok {
			ops = append(ops, parseConcatenationNode(n))
		}
	}
	if len(ops) == 1 {
		return ops[0]
	}
	return altOperator{fmtNodeValue(n), ops}
}

func parseConcatenationNode(n abnf.Node) operator {
	ops := []operator{
		parseRepetitionNode(mustGetNode(n, "repetition")),
	}
	// traverse '*(1*c-wsp repetition)' part
	for _, n := range n.Children[1].Children {
		if n, ok := n.GetNode("repetition"); ok {
			ops = append(ops, parseRepetitionNode(n))
		}
	}
	if len(ops) == 1 {
		return ops[0]
	}
	return concatOperator{fmtNodeValue(n), ops}
}

func parseRepetitionNode(n abnf.Node) operator {
	if n.Children[0].IsEmpty() {
		return parseElementNode(mustGetNode(n, "element"))
	}
	v1, v2 := parseRepeatNode(mustGetNode(n, "repeat"))
	return repeatOperator{
		fmtNodeValue(n),
		parseElementNode(mustGetNode(n, "element")),
		v1, v2,
	}
}

func parseRepeatNode(n abnf.Node) (min, max uint) {
	if n.Contains("1*DIGIT") {
		v, _ := strconv.ParseUint(n.String(), 10, 32)
		return uint(v), uint(v)
	}
	astrx := false
	for _, n := range mustGetNode(n, "*DIGIT \"*\" *DIGIT").Children {
		if n.Key == "*DIGIT" {
			if n.IsEmpty() {
				continue
			}
			if !astrx {
				v, _ := strconv.ParseUint(n.String(), 10, 32)
				min = uint(v)
			} else {
				v, _ := strconv.ParseUint(n.String(), 10, 32)
				max = uint(v)
			}
		} else {
			astrx = true
		}
	}
	return
}

func parseElementNode(n abnf.Node) operator {
	switch n := n.Children[0]; n.Key {
	case "rulename":
		return parseRulenameNode(n)
	case "group":
		return parseGroupNode(n)
	case "option":
		return parseOptionNode(n)
	case "char-val":
		return parseCharValNode(n)
	case "num-val":
		return parseNumValNode(n)
	case "prose-val":
		return parseProseValNode(n)
	default:
		return nil
	}
}

func parseRulenameNode(n abnf.Node) operator {
	return ruleNameOperator{fmtNodeValue(n)}
}

func parseGroupNode(n abnf.Node) operator {
	return parseAlternationNode(mustGetNode(n, "alternation"))
}

func parseOptionNode(n abnf.Node) operator {
	return optionOperator{fmtNodeValue(n), parseAlternationNode(mustGetNode(n, "alternation"))}
}

func parseCharValNode(n abnf.Node) operator {
	return charValOperator{
		fmtNodeValue(mustGetNode(n, "*(%x20-21 / %x23-7E)")),
		n.Contains("case-sensitive-string"),
	}
}

func parseNumValNode(n abnf.Node) operator {
	vn := n.Children[1].Children[0]
	var (
		valKey string
		typ    numType
	)
	switch vn.Key {
	case "bin-val":
		valKey = "1*BIT"
		typ = binNum
	case "dec-val":
		valKey = "1*DIGIT"
		typ = decNum
	case "hex-val":
		valKey = "1*HEXDIG"
		typ = hexNum
	}

	isRange := false
	vals := make([]string, 0, 1)
	for _, n := range vn.Children {
		if n.Contains("\"-\"") {
			isRange = true
		}
		for _, n := range n.GetNodes(valKey) {
			vals = append(vals, n.String())
		}
	}

	return numValOperator{fmtNodeValue(n), typ, vals, isRange}
}

func parseProseValNode(_ abnf.Node) operator {
	panic("prose-val isn't supported")
}

var spRegex = regexp.MustCompile(`\s+`)

func fmtNodeValue(n abnf.Node) string {
	return strings.TrimSpace(spRegex.ReplaceAllString(n.String(), " "))
}

func mustGetNode(n abnf.Node, key string) abnf.Node {
	sn, ok := n.GetNode(key)
	if !ok {
		panic(fmt.Errorf("node '%s' not found", key))
	}
	return sn
}
