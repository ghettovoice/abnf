// This file is generated by abnf - DO NOT EDIT.

package abnf_def

import (
	"github.com/ghettovoice/abnf"
	"github.com/ghettovoice/abnf/pkg/abnf_core"
)

var alternation abnf.Operator

// Alternation rule: alternation = concatenation *(*c-wsp "/" *c-wsp concatenation)
func Alternation(s []byte, ns abnf.Nodes) abnf.Nodes {
	if alternation == nil {
		alternation = abnf.Concat(
			"alternation",
			Concatenation,
			abnf.Repeat0Inf("*(*c-wsp \"/\" *c-wsp concatenation)", abnf.Concat(
				"*c-wsp \"/\" *c-wsp concatenation",
				abnf.Repeat0Inf("*c-wsp", CWsp),
				abnf.Literal("\"/\"", []byte{47}),
				abnf.Repeat0Inf("*c-wsp", CWsp),
				Concatenation,
			)),
		)
	}
	return alternation(s, ns)
}

var binVal abnf.Operator

// BinVal rule: bin-val = "b" 1*BIT [ 1*("." 1*BIT) / ("-" 1*BIT) ]
func BinVal(s []byte, ns abnf.Nodes) abnf.Nodes {
	if binVal == nil {
		binVal = abnf.Concat(
			"bin-val",
			abnf.Literal("\"b\"", []byte{98}),
			abnf.Repeat1Inf("1*BIT", abnf_core.BIT),
			abnf.Optional("[ 1*(\".\" 1*BIT) / (\"-\" 1*BIT) ]", abnf.Alt(
				"1*(\".\" 1*BIT) / (\"-\" 1*BIT)",
				abnf.Repeat1Inf("1*(\".\" 1*BIT)", abnf.Concat(
					"\".\" 1*BIT",
					abnf.Literal("\".\"", []byte{46}),
					abnf.Repeat1Inf("1*BIT", abnf_core.BIT),
				)),
				abnf.Concat(
					"\"-\" 1*BIT",
					abnf.Literal("\"-\"", []byte{45}),
					abnf.Repeat1Inf("1*BIT", abnf_core.BIT),
				),
			)),
		)
	}
	return binVal(s, ns)
}

var cNl abnf.Operator

// CNl rule: c-nl = comment / CRLF
func CNl(s []byte, ns abnf.Nodes) abnf.Nodes {
	if cNl == nil {
		cNl = abnf.Alt(
			"c-nl",
			Comment,
			abnf_core.CRLF,
		)
	}
	return cNl(s, ns)
}

var cWsp abnf.Operator

// CWsp rule: c-wsp = WSP / (c-nl WSP)
func CWsp(s []byte, ns abnf.Nodes) abnf.Nodes {
	if cWsp == nil {
		cWsp = abnf.Alt(
			"c-wsp",
			abnf_core.WSP,
			abnf.Concat(
				"c-nl WSP",
				CNl,
				abnf_core.WSP,
			),
		)
	}
	return cWsp(s, ns)
}

var caseInsensitiveString abnf.Operator

// CaseInsensitiveString rule: case-insensitive-string = [ "%i" ] quoted-string
func CaseInsensitiveString(s []byte, ns abnf.Nodes) abnf.Nodes {
	if caseInsensitiveString == nil {
		caseInsensitiveString = abnf.Concat(
			"case-insensitive-string",
			abnf.Optional("[ \"%i\" ]", abnf.Literal("\"%i\"", []byte{37, 105})),
			QuotedString,
		)
	}
	return caseInsensitiveString(s, ns)
}

var caseSensitiveString abnf.Operator

// CaseSensitiveString rule: case-sensitive-string = "%s" quoted-string
func CaseSensitiveString(s []byte, ns abnf.Nodes) abnf.Nodes {
	if caseSensitiveString == nil {
		caseSensitiveString = abnf.Concat(
			"case-sensitive-string",
			abnf.Literal("\"%s\"", []byte{37, 115}),
			QuotedString,
		)
	}
	return caseSensitiveString(s, ns)
}

var charVal abnf.Operator

// CharVal rule: char-val = case-insensitive-string / case-sensitive-string
func CharVal(s []byte, ns abnf.Nodes) abnf.Nodes {
	if charVal == nil {
		charVal = abnf.Alt(
			"char-val",
			CaseInsensitiveString,
			CaseSensitiveString,
		)
	}
	return charVal(s, ns)
}

var comment abnf.Operator

// Comment rule: comment = ";" *(WSP / VCHAR) CRLF
func Comment(s []byte, ns abnf.Nodes) abnf.Nodes {
	if comment == nil {
		comment = abnf.Concat(
			"comment",
			abnf.Literal("\";\"", []byte{59}),
			abnf.Repeat0Inf("*(WSP / VCHAR)", abnf.Alt(
				"WSP / VCHAR",
				abnf_core.WSP,
				abnf_core.VCHAR,
			)),
			abnf_core.CRLF,
		)
	}
	return comment(s, ns)
}

var concatenation abnf.Operator

// Concatenation rule: concatenation = repetition *(1*c-wsp repetition)
func Concatenation(s []byte, ns abnf.Nodes) abnf.Nodes {
	if concatenation == nil {
		concatenation = abnf.Concat(
			"concatenation",
			Repetition,
			abnf.Repeat0Inf("*(1*c-wsp repetition)", abnf.Concat(
				"1*c-wsp repetition",
				abnf.Repeat1Inf("1*c-wsp", CWsp),
				Repetition,
			)),
		)
	}
	return concatenation(s, ns)
}

var decVal abnf.Operator

// DecVal rule: dec-val = "d" 1*DIGIT [ 1*("." 1*DIGIT) / ("-" 1*DIGIT) ]
func DecVal(s []byte, ns abnf.Nodes) abnf.Nodes {
	if decVal == nil {
		decVal = abnf.Concat(
			"dec-val",
			abnf.Literal("\"d\"", []byte{100}),
			abnf.Repeat1Inf("1*DIGIT", abnf_core.DIGIT),
			abnf.Optional("[ 1*(\".\" 1*DIGIT) / (\"-\" 1*DIGIT) ]", abnf.Alt(
				"1*(\".\" 1*DIGIT) / (\"-\" 1*DIGIT)",
				abnf.Repeat1Inf("1*(\".\" 1*DIGIT)", abnf.Concat(
					"\".\" 1*DIGIT",
					abnf.Literal("\".\"", []byte{46}),
					abnf.Repeat1Inf("1*DIGIT", abnf_core.DIGIT),
				)),
				abnf.Concat(
					"\"-\" 1*DIGIT",
					abnf.Literal("\"-\"", []byte{45}),
					abnf.Repeat1Inf("1*DIGIT", abnf_core.DIGIT),
				),
			)),
		)
	}
	return decVal(s, ns)
}

var definedAs abnf.Operator

// DefinedAs rule: defined-as = *c-wsp ("=" / "=/") *c-wsp
func DefinedAs(s []byte, ns abnf.Nodes) abnf.Nodes {
	if definedAs == nil {
		definedAs = abnf.Concat(
			"defined-as",
			abnf.Repeat0Inf("*c-wsp", CWsp),
			abnf.Alt(
				"\"=\" / \"=/\"",
				abnf.Literal("\"=\"", []byte{61}),
				abnf.Literal("\"=/\"", []byte{61, 47}),
			),
			abnf.Repeat0Inf("*c-wsp", CWsp),
		)
	}
	return definedAs(s, ns)
}

var element abnf.Operator

// Element rule: element = rulename / group / option / char-val / num-val / prose-val
func Element(s []byte, ns abnf.Nodes) abnf.Nodes {
	if element == nil {
		element = abnf.Alt(
			"element",
			Rulename,
			Group,
			Option,
			CharVal,
			NumVal,
			ProseVal,
		)
	}
	return element(s, ns)
}

var elements abnf.Operator

// Elements rule: elements = alternation *WSP
func Elements(s []byte, ns abnf.Nodes) abnf.Nodes {
	if elements == nil {
		elements = abnf.Concat(
			"elements",
			Alternation,
			abnf.Repeat0Inf("*WSP", abnf_core.WSP),
		)
	}
	return elements(s, ns)
}

var group abnf.Operator

// Group rule: group = "(" *c-wsp alternation *c-wsp ")"
func Group(s []byte, ns abnf.Nodes) abnf.Nodes {
	if group == nil {
		group = abnf.Concat(
			"group",
			abnf.Literal("\"(\"", []byte{40}),
			abnf.Repeat0Inf("*c-wsp", CWsp),
			Alternation,
			abnf.Repeat0Inf("*c-wsp", CWsp),
			abnf.Literal("\")\"", []byte{41}),
		)
	}
	return group(s, ns)
}

var hexVal abnf.Operator

// HexVal rule: hex-val = "x" 1*HEXDIG [ 1*("." 1*HEXDIG) / ("-" 1*HEXDIG) ]
func HexVal(s []byte, ns abnf.Nodes) abnf.Nodes {
	if hexVal == nil {
		hexVal = abnf.Concat(
			"hex-val",
			abnf.Literal("\"x\"", []byte{120}),
			abnf.Repeat1Inf("1*HEXDIG", abnf_core.HEXDIG),
			abnf.Optional("[ 1*(\".\" 1*HEXDIG) / (\"-\" 1*HEXDIG) ]", abnf.Alt(
				"1*(\".\" 1*HEXDIG) / (\"-\" 1*HEXDIG)",
				abnf.Repeat1Inf("1*(\".\" 1*HEXDIG)", abnf.Concat(
					"\".\" 1*HEXDIG",
					abnf.Literal("\".\"", []byte{46}),
					abnf.Repeat1Inf("1*HEXDIG", abnf_core.HEXDIG),
				)),
				abnf.Concat(
					"\"-\" 1*HEXDIG",
					abnf.Literal("\"-\"", []byte{45}),
					abnf.Repeat1Inf("1*HEXDIG", abnf_core.HEXDIG),
				),
			)),
		)
	}
	return hexVal(s, ns)
}

var numVal abnf.Operator

// NumVal rule: num-val = "%" (bin-val / dec-val / hex-val)
func NumVal(s []byte, ns abnf.Nodes) abnf.Nodes {
	if numVal == nil {
		numVal = abnf.Concat(
			"num-val",
			abnf.Literal("\"%\"", []byte{37}),
			abnf.Alt(
				"bin-val / dec-val / hex-val",
				BinVal,
				DecVal,
				HexVal,
			),
		)
	}
	return numVal(s, ns)
}

var option abnf.Operator

// Option rule: option = "[" *c-wsp alternation *c-wsp "]"
func Option(s []byte, ns abnf.Nodes) abnf.Nodes {
	if option == nil {
		option = abnf.Concat(
			"option",
			abnf.Literal("\"[\"", []byte{91}),
			abnf.Repeat0Inf("*c-wsp", CWsp),
			Alternation,
			abnf.Repeat0Inf("*c-wsp", CWsp),
			abnf.Literal("\"]\"", []byte{93}),
		)
	}
	return option(s, ns)
}

var proseVal abnf.Operator

// ProseVal rule: prose-val = "<" *(%x20-3D / %x3F-7E) ">"
func ProseVal(s []byte, ns abnf.Nodes) abnf.Nodes {
	if proseVal == nil {
		proseVal = abnf.Concat(
			"prose-val",
			abnf.Literal("\"<\"", []byte{60}),
			abnf.Repeat0Inf("*(%x20-3D / %x3F-7E)", abnf.Alt(
				"%x20-3D / %x3F-7E",
				abnf.Range("%x20-3D", []byte{32}, []byte{61}),
				abnf.Range("%x3F-7E", []byte{63}, []byte{126}),
			)),
			abnf.Literal("\">\"", []byte{62}),
		)
	}
	return proseVal(s, ns)
}

var quotedString abnf.Operator

// QuotedString rule: quoted-string = DQUOTE *(%x20-21 / %x23-7E) DQUOTE
func QuotedString(s []byte, ns abnf.Nodes) abnf.Nodes {
	if quotedString == nil {
		quotedString = abnf.Concat(
			"quoted-string",
			abnf_core.DQUOTE,
			abnf.Repeat0Inf("*(%x20-21 / %x23-7E)", abnf.Alt(
				"%x20-21 / %x23-7E",
				abnf.Range("%x20-21", []byte{32}, []byte{33}),
				abnf.Range("%x23-7E", []byte{35}, []byte{126}),
			)),
			abnf_core.DQUOTE,
		)
	}
	return quotedString(s, ns)
}

var repeat abnf.Operator

// Repeat rule: repeat = 1*DIGIT / (*DIGIT "*" *DIGIT)
func Repeat(s []byte, ns abnf.Nodes) abnf.Nodes {
	if repeat == nil {
		repeat = abnf.Alt(
			"repeat",
			abnf.Repeat1Inf("1*DIGIT", abnf_core.DIGIT),
			abnf.Concat(
				"*DIGIT \"*\" *DIGIT",
				abnf.Repeat0Inf("*DIGIT", abnf_core.DIGIT),
				abnf.Literal("\"*\"", []byte{42}),
				abnf.Repeat0Inf("*DIGIT", abnf_core.DIGIT),
			),
		)
	}
	return repeat(s, ns)
}

var repetition abnf.Operator

// Repetition rule: repetition = [repeat] element
func Repetition(s []byte, ns abnf.Nodes) abnf.Nodes {
	if repetition == nil {
		repetition = abnf.Concat(
			"repetition",
			abnf.Optional("[repeat]", Repeat),
			Element,
		)
	}
	return repetition(s, ns)
}

var rule abnf.Operator

// Rule rule: rule = rulename defined-as elements c-nl
func Rule(s []byte, ns abnf.Nodes) abnf.Nodes {
	if rule == nil {
		rule = abnf.Concat(
			"rule",
			Rulename,
			DefinedAs,
			Elements,
			CNl,
		)
	}
	return rule(s, ns)
}

var rulelist abnf.Operator

// Rulelist rule: rulelist = 1*( rule / (*WSP c-nl) )
func Rulelist(s []byte, ns abnf.Nodes) abnf.Nodes {
	if rulelist == nil {
		rulelist = abnf.Repeat1Inf("rulelist", abnf.Alt(
			"rule / (*WSP c-nl)",
			Rule,
			abnf.Concat(
				"*WSP c-nl",
				abnf.Repeat0Inf("*WSP", abnf_core.WSP),
				CNl,
			),
		))
	}
	return rulelist(s, ns)
}

var rulename abnf.Operator

// Rulename rule: rulename = ALPHA *(ALPHA / DIGIT / "-")
func Rulename(s []byte, ns abnf.Nodes) abnf.Nodes {
	if rulename == nil {
		rulename = abnf.Concat(
			"rulename",
			abnf_core.ALPHA,
			abnf.Repeat0Inf("*(ALPHA / DIGIT / \"-\")", abnf.Alt(
				"ALPHA / DIGIT / \"-\"",
				abnf_core.ALPHA,
				abnf_core.DIGIT,
				abnf.Literal("\"-\"", []byte{45}),
			)),
		)
	}
	return rulename(s, ns)
}
