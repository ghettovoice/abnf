package abnf_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/ghettovoice/abnf"
)

var (
	a = abnf.Literal("a", []byte("a"))
	b = abnf.Literal("b", []byte("b"))
	c = abnf.Literal("c", []byte("c"))
)

var _ = Describe("Operators", func() {
	assertFn := func(p abnf.Operator, s []byte, expect abnf.Nodes) {
		Expect(p(s, nil)).Should(Equal(expect))
	}

	Describe("literal", func() {
		p1 := abnf.Literal("qwe", []byte("qwe"))
		p2 := abnf.LiteralCS("Qwe", []byte("Qwe"))

		DescribeTable("", assertFn,
			Entry(`"qwe", in=Qwerty`, p1, []byte("Qwerty"),
				abnf.Nodes{
					{Key: "qwe", Value: []byte("Qwe")},
				},
			),
			Entry(`"qwe", in=abc`, p1, []byte("abc"), nil),
			Entry(`"м", in=МИР"`,
				abnf.Literal("м", []byte("м")),
				[]byte("МИР"),
				abnf.Nodes{
					{Key: "м", Value: []byte("М")},
				},
			),
			Entry(`"abc", in=a`,
				abnf.Literal("abc", []byte("abc")),
				[]byte("a"),
				nil,
			),
			Entry(`%s"Qwe", in=Qwerty`, p2, []byte("Qwerty"),
				abnf.Nodes{
					{Key: "Qwe", Value: []byte("Qwe")},
				},
			),
			Entry(`%s"Qwe", in=qwerty`, p2, []byte("qwerty"), nil),
		)
	})

	Describe("range", func() {
		DescribeTable("", assertFn,
			Entry("%x61-7A, in=qwe",
				abnf.Range("%x61-7A", []byte{97}, []byte{122}),
				[]byte("qwe"),
				abnf.Nodes{
					{Key: "%x61-7A", Value: []byte("q")},
				},
			),
			Entry("%x41-5A, in=abc",
				abnf.Range("%x41-5A", []byte{65}, []byte{90}),
				[]byte("abc"),
				nil,
			),
			Entry("%x6121-7A21, in=a",
				abnf.Range("%x6121-7A21", []byte{97, 33}, []byte{122, 33}),
				[]byte("a"),
				nil,
			),
			Entry("%x5D-10FFFF, in=xxx",
				abnf.Range("%x5D-10FFFF", []byte{93}, []byte{16, 255, 255}),
				[]byte("xxx"),
				abnf.Nodes{
					{Key: "%x5D-10FFFF", Value: []byte("x")},
				},
			),
		)
	})

	Describe("alternation", func() {
		p1 := abnf.Alt(`"a" / "b"`, a, b)
		p2 := abnf.Alt(`"a" / "ab"`, a, abnf.Literal("ab", []byte("ab")))
		p3 := abnf.AltFirst(`"a" / "ab"`, a, abnf.Literal("ab", []byte("ab")))

		DescribeTable("", assertFn,
			Entry(`"a" / "b", in=a`, p1, []byte("a"),
				abnf.Nodes{
					{
						Key:   `"a" / "b"`,
						Value: []byte("a"),
						Children: abnf.Nodes{
							{Key: "a", Value: []byte("a")},
						},
					},
				},
			),
			Entry(`"a" / "b", in=b`, p1, []byte("b"),
				abnf.Nodes{
					{
						Key:   `"a" / "b"`,
						Value: []byte("b"),
						Children: abnf.Nodes{
							{Key: "b", Value: []byte("b")},
						},
					},
				},
			),
			Entry(`"a" / "b", in=c`, p1, []byte("c"), nil),
			Entry(`"a" / "ab", in=abc`, p2, []byte("abc"),
				abnf.Nodes{
					{
						Key:   `"a" / "ab"`,
						Value: []byte("ab"),
						Children: abnf.Nodes{
							{Key: "ab", Value: []byte("ab")},
						},
					},
					{
						Key:   `"a" / "ab"`,
						Value: []byte("a"),
						Children: abnf.Nodes{
							{Key: "a", Value: []byte("a")},
						},
					},
				},
			),
			Entry(`first of "a" / "ab", in=abc`, p3, []byte("abc"),
				abnf.Nodes{
					{
						Key:   `"a" / "ab"`,
						Value: []byte("a"),
						Children: abnf.Nodes{
							{Key: "a", Value: []byte("a")},
						},
					},
				},
			),
		)
	})

	Describe("optional", func() {
		p1 := abnf.Optional(`[ "a" ]`, a)

		DescribeTable("", assertFn,
			Entry(`[ "a" ], in=abc`, p1, []byte("abc"),
				abnf.Nodes{
					{
						Key:   `[ "a" ]`,
						Value: []byte("a"),
						Children: abnf.Nodes{
							{Key: "a", Value: []byte("a")},
						},
					},
					{
						Key:   `[ "a" ]`,
						Value: []byte{},
					},
				},
			),
			Entry(`[ "a" ], in=bbc`, p1, []byte("bbc"),
				abnf.Nodes{
					{
						Key:   `[ "a" ]`,
						Value: []byte{},
					},
				},
			),
		)
	})

	Describe("repeating", func() {
		p1 := abnf.Repeat(`*1( "a" )`, 0, 1, a)
		p2 := abnf.Repeat(`2*3( "a" )`, 2, 3, a)
		p3 := abnf.RepeatN(`3( "a" )`, 3, a)
		p4 := abnf.Repeat0Inf(`*( "a" )`, a)
		p5 := abnf.Repeat1Inf(`1*( "a" )`, a)

		DescribeTable("", assertFn,
			Entry(`*1( "a" ), in=aaa`, p1, []byte("aaa"),
				abnf.Nodes{
					{
						Key:   `*1( "a" )`,
						Value: []byte("a"),
						Children: abnf.Nodes{
							{Key: "a", Value: []byte("a")},
						},
					},
					{
						Key:   `*1( "a" )`,
						Value: []byte{},
					},
				},
			),
			Entry(`*1( "a" ), in=bbb`, p1, []byte("bbb"),
				abnf.Nodes{
					{
						Key:   `*1( "a" )`,
						Value: []byte{},
					},
				},
			),
			Entry(`2*3( "a" ), in=a`, p2, []byte("a"), abnf.Nodes{}),
			Entry(`2*3( "a" ), in=aa`, p2, []byte("aa"),
				abnf.Nodes{
					{
						Key:   `2*3( "a" )`,
						Value: []byte("aa"),
						Children: abnf.Nodes{
							{Key: "a", Value: []byte("a")},
							{Key: "a", Value: []byte("a")},
						},
					},
				},
			),
			Entry(`2*3( "a" ), in=aaa`, p2, []byte("aaa"),
				abnf.Nodes{
					{
						Key:   `2*3( "a" )`,
						Value: []byte("aaa"),
						Children: abnf.Nodes{
							{Key: "a", Value: []byte("a")},
							{Key: "a", Value: []byte("a")},
							{Key: "a", Value: []byte("a")},
						},
					},
					{
						Key:   `2*3( "a" )`,
						Value: []byte("aa"),
						Children: abnf.Nodes{
							{Key: "a", Value: []byte("a")},
							{Key: "a", Value: []byte("a")},
						},
					},
				},
			),
			Entry("max > min, in=aaa", abnf.Repeat("", 10, 5, a), []byte("aaa"), nil),
			Entry(`3( "a" ), in=aa`, p3, []byte("aa"), abnf.Nodes{}),
			Entry(`3( "a" ), in=aaaa`, p3, []byte("aaaa"), abnf.Nodes{
				{
					Key:   `3( "a" )`,
					Value: []byte("aaa"),
					Children: abnf.Nodes{
						{Key: "a", Value: []byte("a")},
						{Key: "a", Value: []byte("a")},
						{Key: "a", Value: []byte("a")},
					},
				},
			}),
			Entry(`*( "a" ), in=`, p4, []byte(""), abnf.Nodes{
				{
					Key:   `*( "a" )`,
					Value: []byte(""),
				},
			}),
			Entry(`*( "a" ), in=aaa`, p4, []byte("aaa"), abnf.Nodes{
				{
					Key:   `*( "a" )`,
					Value: []byte("aaa"),
					Children: abnf.Nodes{
						{Key: "a", Value: []byte("a")},
						{Key: "a", Value: []byte("a")},
						{Key: "a", Value: []byte("a")},
					},
				},
				{
					Key:   `*( "a" )`,
					Value: []byte("aa"),
					Children: abnf.Nodes{
						{Key: "a", Value: []byte("a")},
						{Key: "a", Value: []byte("a")},
					},
				},
				{
					Key:   `*( "a" )`,
					Value: []byte("a"),
					Children: abnf.Nodes{
						{Key: "a", Value: []byte("a")},
					},
				},
				{
					Key:   `*( "a" )`,
					Value: []byte(""),
				},
			}),
			Entry(`1*( "a" ), in=aaa`, p5, []byte("aaa"), abnf.Nodes{
				{
					Key:   `1*( "a" )`,
					Value: []byte("aaa"),
					Children: abnf.Nodes{
						{Key: "a", Value: []byte("a")},
						{Key: "a", Value: []byte("a")},
						{Key: "a", Value: []byte("a")},
					},
				},
				{
					Key:   `1*( "a" )`,
					Value: []byte("aa"),
					Children: abnf.Nodes{
						{Key: "a", Value: []byte("a")},
						{Key: "a", Value: []byte("a")},
					},
				},
				{
					Key:   `1*( "a" )`,
					Value: []byte("a"),
					Children: abnf.Nodes{
						{Key: "a", Value: []byte("a")},
					},
				},
			}),
			Entry(`1*( "a" ), in=a`, p5, []byte("a"), abnf.Nodes{
				{
					Key:   `1*( "a" )`,
					Value: []byte("a"),
					Children: abnf.Nodes{
						{Key: "a", Value: []byte("a")},
					},
				},
			}),
			Entry(`1*( "a" ), in=b`, p5, []byte("b"), abnf.Nodes{}),
		)
	})

	Describe("concatenation", func() {
		p1 := abnf.Concat(`"a" "b" "c"`, a, b, c)

		DescribeTable("", assertFn,
			Entry(`"a" "b" "c", in=abc`, p1, []byte("abc"),
				abnf.Nodes{
					{
						Key:   `"a" "b" "c"`,
						Value: []byte("abc"),
						Children: abnf.Nodes{
							{Key: "a", Value: []byte("a")},
							{Key: "b", Value: []byte("b")},
							{Key: "c", Value: []byte("c")},
						},
					},
				},
			),
			Entry(`"a" "b" "c", in=abz`, p1, []byte("abz"), abnf.Nodes{}),
			Entry("no rules, in=abc",
				abnf.Concat(""),
				[]byte("abc"),
				nil,
			),
		)
	})

	Describe("combinations", func() {
		p1 := abnf.ConcatAll(`[ "a" ] "a"`,
			abnf.Optional(`[ "a" ]`, a),
			a,
		)
		p2 := abnf.Repeat0Inf(`*( [ "a" ] )`, abnf.Optional(`[ "a" ]`, a))
		p3 := abnf.Concat(`"a" *( "a" / "b" ) "a"`,
			a,
			abnf.Repeat0Inf(`*( "a" / "b" )`, abnf.Alt(`"a" / "b"`, a, b)),
			a,
		)
		p4 := abnf.Concat(`(*"a" / *"b") "a"`,
			abnf.Alt(`*"a" / *"b"`,
				abnf.Repeat0Inf(`*"a"`, a),
				abnf.Repeat0Inf(`*"b"`, b),
			),
			a,
		)

		DescribeTable("", assertFn,
			Entry(`[ "a" ] "bc", in=abc`,
				abnf.Concat(`[ "a" ] "bc"`,
					abnf.Optional(`[ "a" ]`, a),
					abnf.Literal("bc", []byte("bc")),
				),
				[]byte("abc"),
				abnf.Nodes{
					{
						Key:   `[ "a" ] "bc"`,
						Value: []byte("abc"),
						Children: abnf.Nodes{
							{
								Key:   `[ "a" ]`,
								Value: []byte("a"),
								Children: abnf.Nodes{
									{Key: "a", Value: []byte("a")},
								},
							},
							{Key: "bc", Value: []byte("bc")},
						},
					},
				},
			),
			Entry(`[ "a" ] "abc", in=abc`,
				abnf.Concat(`[ "a" ] "abc"`,
					abnf.Optional(`[ "a" ]`, a),
					abnf.Literal("abc", []byte("abc")),
				),
				[]byte("abc"),
				abnf.Nodes{
					{
						Key:   `[ "a" ] "abc"`,
						Value: []byte("abc"),
						Children: abnf.Nodes{
							{
								Key:   `[ "a" ]`,
								Value: []byte{},
							},
							{Key: "abc", Value: []byte("abc")},
						},
					},
				},
			),
			Entry(`[ "a" ] "a", in=aa`,
				abnf.Concat(`[ "a" ] "a"`,
					abnf.Optional(`[ "a" ]`, a),
					a,
				),
				[]byte("aa"),
				abnf.Nodes{
					{
						Key:   `[ "a" ] "a"`,
						Value: []byte("aa"),
						Children: abnf.Nodes{
							{
								Key:   `[ "a" ]`,
								Value: []byte("a"),
								Children: abnf.Nodes{
									{Key: "a", Value: []byte("a")},
								},
							},
							{Key: "a", Value: []byte("a")},
						},
					},
				},
			),
			Entry(`all of [ "a" ] "a", in=aa`, p1, []byte("aa"),
				abnf.Nodes{
					{
						Key:   `[ "a" ] "a"`,
						Value: []byte("aa"),
						Children: abnf.Nodes{
							{
								Key:   `[ "a" ]`,
								Value: []byte("a"),
								Children: abnf.Nodes{
									{Key: "a", Value: []byte("a")},
								},
							},
							{Key: "a", Value: []byte("a")},
						},
					},
					{
						Key:   `[ "a" ] "a"`,
						Value: []byte("a"),
						Children: abnf.Nodes{
							{Key: `[ "a" ]`, Value: []byte("")},
							{Key: "a", Value: []byte("a")},
						},
					},
				},
			),
			Entry(`[ "a" ] "a", in=a`, p1, []byte("a"),
				abnf.Nodes{
					{
						Key:   `[ "a" ] "a"`,
						Value: []byte("a"),
						Children: abnf.Nodes{
							{Key: `[ "a" ]`, Value: []byte("")},
							{Key: "a", Value: []byte("a")},
						},
					},
				},
			),
			Entry(`*( [ "a" ] ), in=`, p2, []byte(""),
				abnf.Nodes{
					{
						Key:   `*( [ "a" ] )`,
						Value: []byte(""),
					},
				},
			),
			Entry(`*( [ "a" ] ), in=aa`, p2, []byte("aa"),
				abnf.Nodes{
					{
						Key:   `*( [ "a" ] )`,
						Value: []byte("aa"),
						Children: abnf.Nodes{
							{
								Key:   `[ "a" ]`,
								Value: []byte("a"),
								Children: abnf.Nodes{
									{Key: "a", Value: []byte("a")},
								},
							},
							{
								Key:   `[ "a" ]`,
								Value: []byte("a"),
								Children: abnf.Nodes{
									{Key: "a", Value: []byte("a")},
								},
							},
						},
					},
					{
						Key:   `*( [ "a" ] )`,
						Value: []byte("a"),
						Children: abnf.Nodes{
							{
								Key:   `[ "a" ]`,
								Value: []byte("a"),
								Children: abnf.Nodes{
									{Key: "a", Value: []byte("a")},
								},
							},
							{Key: `[ "a" ]`, Value: []byte("")},
						},
					},
					{
						Key:   `*( [ "a" ] )`,
						Value: []byte("a"),
						Children: abnf.Nodes{
							{Key: `[ "a" ]`, Value: []byte("")},
							{
								Key:   `[ "a" ]`,
								Value: []byte("a"),
								Children: abnf.Nodes{
									{Key: "a", Value: []byte("a")},
								},
							},
						},
					},
					{
						Key:   `*( [ "a" ] )`,
						Value: []byte(""),
						Children: abnf.Nodes{
							{Key: `[ "a" ]`, Value: []byte("")},
							{Key: `[ "a" ]`, Value: []byte("")},
						},
					},
					{
						Key:   `*( [ "a" ] )`,
						Value: []byte("a"),
						Children: abnf.Nodes{
							{
								Key:   `[ "a" ]`,
								Value: []byte("a"),
								Children: abnf.Nodes{
									{Key: "a", Value: []byte("a")},
								},
							},
						},
					},
					{
						Key:   `*( [ "a" ] )`,
						Value: []byte(""),
						Children: abnf.Nodes{
							{Key: `[ "a" ]`, Value: []byte("")},
						},
					},
					{
						Key:   `*( [ "a" ] )`,
						Value: []byte(""),
					},
				},
			),
			Entry(`"a" *( "a" / "b" ) "a", in=aa`, p3, []byte("aa"),
				abnf.Nodes{
					{
						Key:   `"a" *( "a" / "b" ) "a"`,
						Value: []byte("aa"),
						Children: abnf.Nodes{
							{Key: "a", Value: []byte("a")},
							{Key: `*( "a" / "b" )`, Value: []byte("")},
							{Key: "a", Value: []byte("a")},
						},
					},
				},
			),
			Entry(`"a" *( "a" / "b" ) "a", in=aaa`, p3, []byte("aaa"),
				abnf.Nodes{
					{
						Key:   `"a" *( "a" / "b" ) "a"`,
						Value: []byte("aaa"),
						Children: abnf.Nodes{
							{Key: "a", Value: []byte("a")},
							{
								Key:   `*( "a" / "b" )`,
								Value: []byte("a"),
								Children: abnf.Nodes{
									{
										Key:   `"a" / "b"`,
										Value: []byte("a"),
										Children: abnf.Nodes{
											{Key: "a", Value: []byte("a")},
										},
									},
								},
							},
							{Key: "a", Value: []byte("a")},
						},
					},
				},
			),
			Entry(`"a" *( "a" / "b" ) "a", in=aaba`, p3, []byte("aaba"),
				abnf.Nodes{
					{
						Key:   `"a" *( "a" / "b" ) "a"`,
						Value: []byte("aaba"),
						Children: abnf.Nodes{
							{Key: "a", Value: []byte("a")},
							{
								Key:   `*( "a" / "b" )`,
								Value: []byte("ab"),
								Children: abnf.Nodes{
									{
										Key:   `"a" / "b"`,
										Value: []byte("a"),
										Children: abnf.Nodes{
											{Key: "a", Value: []byte("a")},
										},
									},
									{
										Key:   `"a" / "b"`,
										Value: []byte("b"),
										Children: abnf.Nodes{
											{Key: "b", Value: []byte("b")},
										},
									},
								},
							},
							{Key: "a", Value: []byte("a")},
						},
					},
				},
			),
			Entry(`(*"a" / *"b") "a", in=a`, p4, []byte("a"),
				abnf.Nodes{
					{
						Key:   `(*"a" / *"b") "a"`,
						Value: []byte("a"),
						Children: abnf.Nodes{
							{
								Key:   `*"a" / *"b"`,
								Value: []byte(""),
								Children: abnf.Nodes{
									{Key: `*"a"`, Value: []byte("")},
								},
							},
							{Key: "a", Value: []byte("a")},
						},
					},
				},
			),
			Entry(`(*"a" / *"b") "a", in=aa`, p4, []byte("aa"),
				abnf.Nodes{
					{
						Key:   `(*"a" / *"b") "a"`,
						Value: []byte("aa"),
						Children: abnf.Nodes{
							{
								Key:   `*"a" / *"b"`,
								Value: []byte("a"),
								Children: abnf.Nodes{
									{
										Key:   `*"a"`,
										Value: []byte("a"),
										Children: abnf.Nodes{
											{Key: "a", Value: []byte("a")},
										},
									},
								},
							},
							{Key: "a", Value: []byte("a")},
						},
					},
				},
			),
		)
	})
})

func BenchmarkLiteral(b *testing.B) {
	p := abnf.Literal("z", []byte("z"))
	in := []byte("zzz")
	ns := make(abnf.Nodes, 0, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ns = ns[:0]
		ns = p(in, ns)
		if len(ns) != 1 {
			b.Errorf("expected 1 node, got %d", len(ns))
		}
	}
}

func BenchmarkLiteral_unicode(b *testing.B) {
	p := abnf.Literal("м", []byte("м"))
	in := []byte("мир")
	ns := make(abnf.Nodes, 0, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ns = ns[:0]
		ns = p(in, ns)
		if len(ns) != 1 {
			b.Errorf("expected 1 node, got %d", len(ns))
		}
	}
}

func BenchmarkLiteralCS(b *testing.B) {
	p := abnf.LiteralCS("Z", []byte("Z"))
	in := []byte("ZZZ")
	ns := make(abnf.Nodes, 0, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ns = ns[:0]
		ns = p(in, ns)
		if len(ns) != 1 {
			b.Errorf("expected 1 node, got %d", len(ns))
		}
	}
}

func BenchmarkRange(b *testing.B) {
	p := abnf.Range("%x61-7A", []byte{97}, []byte{122})
	in := []byte("zzz")
	ns := make(abnf.Nodes, 0, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ns = ns[:0]
		ns = p(in, ns)
		if len(ns) != 1 {
			b.Errorf("expected 1 node, got %d", len(ns))
		}
	}
}

func BenchmarkAlt(tb *testing.B) {
	p := abnf.Alt(`"a" / "b" / "c"`, a, b, c)
	inputs := [][]byte{
		[]byte("a"),
		[]byte("b"),
		[]byte("c"),
	}
	ns := make(abnf.Nodes, 0, 1)

	for _, in := range inputs {
		tb.Run(string(in), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if len(p(in, ns[:0])) == 0 {
					b.Error("expected result, but got nothing")
				}
			}
		})
	}
}

func BenchmarkConcat(b *testing.B) {
	p := abnf.Concat(`"ab" "c"`, abnf.Literal("ab", []byte("ab")), c)
	in := []byte("abc")
	ns := make(abnf.Nodes, 0, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(p(in, ns[:0])) == 0 {
			b.Error("expected result, but got nothing")
		}
	}
}

func BenchmarkRepeat0Inf(b *testing.B) {
	p := abnf.Repeat0Inf(`*"a"`, a)
	inputs := [][]byte{[]byte(""), []byte("a"), []byte("aaa")}
	ns := make(abnf.Nodes, 0, 9)

	b.ResetTimer()
	for _, in := range inputs {
		b.Run(string(in), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if len(p(in, ns[:0])) == 0 {
					b.Error("expected result, but got nothing")
				}
			}
		})
	}
}
