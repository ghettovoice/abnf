package abnf_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/ghettovoice/abnf"
)

func TestOperator(t *testing.T) {
	cases := []struct {
		name    string
		op      abnf.Operator
		in      []byte
		wantNs  abnf.Nodes
		wantErr error
	}{
		{"literal 1",
			abnf.Literal("qwe", []byte("qwe")),
			[]byte("Qwerty"),
			abnf.Nodes{
				{Key: "qwe", Value: []byte("Qwe")},
			},
			nil,
		},
		{"literal 2",
			abnf.Literal("qwe", []byte("qwe")),
			[]byte("qwabc"),
			nil,
			abnf.ErrNotMatched,
		},
		{"literal 3",
			abnf.Literal("м", []byte("м")),
			[]byte("МИР"),
			abnf.Nodes{
				{Key: "м", Value: []byte("М")},
			},
			nil,
		},
		{"literal 4",
			abnf.LiteralCS("Qwe", []byte("Qwe")),
			[]byte("Qwerty"),
			abnf.Nodes{
				{Key: "Qwe", Value: []byte("Qwe")},
			},
			nil,
		},
		{"literal 5",
			abnf.LiteralCS("Qwe", []byte("Qwe")),
			[]byte("qwerty"),
			nil,
			abnf.ErrNotMatched,
		},
		{"literal 6",
			abnf.Literal("qwerty", []byte("qwerty")),
			[]byte("qwe"),
			nil,
			abnf.ErrNotMatched,
		},

		{"range 1",
			abnf.Range("%x61-7A", []byte{97}, []byte{122}),
			[]byte("qwe"),
			abnf.Nodes{
				{Key: "%x61-7A", Value: []byte("q")},
			},
			nil,
		},
		{"range 2",
			abnf.Range("%x41-5A", []byte{65}, []byte{90}),
			[]byte("abc"),
			nil,
			abnf.ErrNotMatched,
		},
		{"range 3",
			abnf.Range("%x6121-7A21", []byte{97, 33}, []byte{122, 33}),
			[]byte("a"),
			nil,
			abnf.ErrNotMatched,
		},
		{"range 4",
			abnf.Range("%x5D-10FFFF", []byte{93}, []byte{16, 255, 255}),
			[]byte("xxx"),
			abnf.Nodes{
				{Key: "%x5D-10FFFF", Value: []byte("x")},
			},
			nil,
		},

		{"alt 1",
			abnf.Alt(`"a" / "b"`,
				abnf.Literal("a", []byte("a")),
				abnf.Literal("b", []byte("b")),
			),
			[]byte("a"),
			abnf.Nodes{
				{
					Key:   `"a" / "b"`,
					Value: []byte("a"),
					Children: abnf.Nodes{
						{Key: "a", Value: []byte("a")},
					},
				},
			},
			nil,
		},
		{"alt 2",
			abnf.Alt(`"a" / "b"`,
				abnf.Literal("a", []byte("a")),
				abnf.Literal("b", []byte("b")),
			),
			[]byte("b"),
			abnf.Nodes{
				{
					Key:   `"a" / "b"`,
					Value: []byte("b"),
					Children: abnf.Nodes{
						{Key: "b", Value: []byte("b")},
					},
				},
			},
			nil,
		},
		{"alt 3",
			abnf.Alt(`"a" / "b"`,
				abnf.Literal("a", []byte("a")),
				abnf.Literal("b", []byte("b")),
			),
			[]byte("c"),
			nil,
			abnf.ErrNotMatched,
		},
		{"alt 4",
			abnf.Alt(`"a" / "ab"`, abnf.Literal(`"a"`, []byte("a")), abnf.Literal(`"ab"`, []byte("ab"))),
			[]byte("abc"),
			abnf.Nodes{
				{
					Key:   `"a" / "ab"`,
					Value: []byte("ab"),
					Children: abnf.Nodes{
						{Key: `"ab"`, Value: []byte("ab")},
					},
				},
				{
					Key:   `"a" / "ab"`,
					Value: []byte("a"),
					Children: abnf.Nodes{
						{Key: `"a"`, Value: []byte("a")},
					},
				},
			},
			nil,
		},
		{"alt 4",
			abnf.AltFirst(`"b" / "a" / "ab"`,
				abnf.Literal(`"b"`, []byte("b")),
				abnf.Literal(`"a"`, []byte("a")),
				abnf.Literal(`"ab"`, []byte("ab")),
			),
			[]byte("abc"),
			abnf.Nodes{
				{
					Key:   `"b" / "a" / "ab"`,
					Value: []byte("a"),
					Children: abnf.Nodes{
						{Key: `"a"`, Value: []byte("a")},
					},
				},
			},
			nil,
		},

		{"concat 1",
			abnf.Concat(`"a" "b" "c"`,
				abnf.Literal("a", []byte("a")),
				abnf.Literal("b", []byte("b")),
				abnf.Literal("c", []byte("c")),
			),
			[]byte("abc"),
			abnf.Nodes{
				{
					Key:   `"a" "b" "c"`,
					Value: []byte("abc"),
					Children: abnf.Nodes{
						{Key: "a", Pos: 0, Value: []byte("a")},
						{Key: "b", Pos: 1, Value: []byte("b")},
						{Key: "c", Pos: 2, Value: []byte("c")},
					},
				},
			},
			nil,
		},
		{"concat 2",
			abnf.Concat(`"a" "b" "c"`,
				abnf.Literal("a", []byte("a")),
				abnf.Literal("b", []byte("b")),
				abnf.Literal("c", []byte("c")),
			),
			[]byte("abz"),
			nil,
			abnf.ErrNotMatched,
		},

		{"opt 1",
			abnf.Optional(`[ "a" ]`, abnf.Literal("a", []byte("a"))),
			[]byte("abc"),
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
			nil,
		},
		{"opt 2",
			abnf.Optional(`[ "a" ]`, abnf.Literal("a", []byte("a"))),
			[]byte("b"),
			abnf.Nodes{
				{
					Key:   `[ "a" ]`,
					Value: []byte{},
				},
			},
			nil,
		},

		{"repeat 1",
			abnf.Repeat(`*1( "a" )`, 0, 1, abnf.Literal("a", []byte("a"))),
			[]byte("aaa"),
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
			nil,
		},
		{"repeat 2",
			abnf.Repeat(`*1( "a" )`, 0, 1, abnf.Literal("a", []byte("a"))),
			[]byte("bbb"),
			abnf.Nodes{
				{
					Key:   `*1( "a" )`,
					Value: []byte{},
				},
			},
			nil,
		},
		{"repeat 3",
			abnf.Repeat(`2*3( "a" )`, 2, 3, abnf.Literal("a", []byte("a"))),
			[]byte("a"),
			nil,
			abnf.ErrNotMatched,
		},
		{"repeat 4",
			abnf.Repeat(`2*3( "a" )`, 2, 3, abnf.Literal("a", []byte("a"))),
			[]byte("aa"),
			abnf.Nodes{
				{
					Key:   `2*3( "a" )`,
					Value: []byte("aa"),
					Children: abnf.Nodes{
						{Key: "a", Pos: 0, Value: []byte("a")},
						{Key: "a", Pos: 1, Value: []byte("a")},
					},
				},
			},
			nil,
		},
		{"repeat 5",
			abnf.Repeat(`2*3( "a" )`, 2, 3, abnf.Literal("a", []byte("a"))),
			[]byte("aaa"),
			abnf.Nodes{
				{
					Key:   `2*3( "a" )`,
					Value: []byte("aaa"),
					Children: abnf.Nodes{
						{Key: "a", Pos: 0, Value: []byte("a")},
						{Key: "a", Pos: 1, Value: []byte("a")},
						{Key: "a", Pos: 2, Value: []byte("a")},
					},
				},
				{
					Key:   `2*3( "a" )`,
					Value: []byte("aa"),
					Children: abnf.Nodes{
						{Key: "a", Pos: 0, Value: []byte("a")},
						{Key: "a", Pos: 1, Value: []byte("a")},
					},
				},
			},
			nil,
		},
		{"repeat 6",
			abnf.Repeat(`3( "a" )`, 3, 2, abnf.Literal("a", []byte("a"))),
			[]byte("aaa"),
			abnf.Nodes{
				{
					Key:   `3( "a" )`,
					Value: []byte("aaa"),
					Children: abnf.Nodes{
						{Key: "a", Pos: 0, Value: []byte("a")},
						{Key: "a", Pos: 1, Value: []byte("a")},
						{Key: "a", Pos: 2, Value: []byte("a")},
					},
				},
			},
			nil,
		},
		{"repeat 7",
			abnf.RepeatN(`3( "a" )`, 3, abnf.Literal("a", []byte("a"))),
			[]byte("aa"),
			nil,
			abnf.ErrNotMatched,
		},
		{"repeat 8",
			abnf.Repeat0Inf(`*( "a" )`, abnf.Literal("a", []byte("a"))),
			[]byte(""),
			abnf.Nodes{
				{Key: `*( "a" )`, Value: []byte{}},
			},
			nil,
		},
		{"repeat 9",
			abnf.Repeat0Inf(`*( "a" )`, abnf.Literal("a", []byte("a"))),
			[]byte("aaa"),
			abnf.Nodes{
				{
					Key:   `*( "a" )`,
					Value: []byte("aaa"),
					Children: abnf.Nodes{
						{Key: "a", Pos: 0, Value: []byte("a")},
						{Key: "a", Pos: 1, Value: []byte("a")},
						{Key: "a", Pos: 2, Value: []byte("a")},
					},
				},
				{
					Key:   `*( "a" )`,
					Value: []byte("aa"),
					Children: abnf.Nodes{
						{Key: "a", Pos: 0, Value: []byte("a")},
						{Key: "a", Pos: 1, Value: []byte("a")},
					},
				},
				{
					Key:   `*( "a" )`,
					Value: []byte("a"),
					Children: abnf.Nodes{
						{Key: "a", Pos: 0, Value: []byte("a")},
					},
				},
				{
					Key:   `*( "a" )`,
					Value: []byte(""),
				},
			},
			nil,
		},
		{"repeat 10",
			abnf.Repeat1Inf(`1*( "a" )`, abnf.Literal("a", []byte("a"))),
			[]byte("aaa"),
			abnf.Nodes{
				{
					Key:   `1*( "a" )`,
					Value: []byte("aaa"),
					Children: abnf.Nodes{
						{Key: "a", Pos: 0, Value: []byte("a")},
						{Key: "a", Pos: 1, Value: []byte("a")},
						{Key: "a", Pos: 2, Value: []byte("a")},
					},
				},
				{
					Key:   `1*( "a" )`,
					Value: []byte("aa"),
					Children: abnf.Nodes{
						{Key: "a", Pos: 0, Value: []byte("a")},
						{Key: "a", Pos: 1, Value: []byte("a")},
					},
				},
				{
					Key:   `1*( "a" )`,
					Value: []byte("a"),
					Children: abnf.Nodes{
						{Key: "a", Pos: 0, Value: []byte("a")},
					},
				},
			},
			nil,
		},
		{"repeat 11",
			abnf.Repeat1Inf(`1*( "a" )`, abnf.Literal("a", []byte("a"))),
			[]byte("a"),
			abnf.Nodes{
				{
					Key:   `1*( "a" )`,
					Value: []byte("a"),
					Children: abnf.Nodes{
						{Key: "a", Pos: 0, Value: []byte("a")},
					},
				},
			},
			nil,
		},
		{"repeat 12",
			abnf.Repeat1Inf(`1*( "a" )`, abnf.Literal("a", []byte("a"))),
			[]byte(""),
			nil,
			abnf.ErrNotMatched,
		},

		{"combo 1",
			abnf.Concat(`[ "a" ] "bc"`,
				abnf.Optional(`[ "a" ]`, abnf.Literal("a", []byte("a"))),
				abnf.Literal("bc", []byte("bc")),
			),
			[]byte("abc"),
			abnf.Nodes{
				{
					Key:   `[ "a" ] "bc"`,
					Pos:   0,
					Value: []byte("abc"),
					Children: abnf.Nodes{
						{
							Key:   `[ "a" ]`,
							Pos:   0,
							Value: []byte("a"),
							Children: abnf.Nodes{
								{Key: "a", Pos: 0, Value: []byte("a")},
							},
						},
						{Key: "bc", Pos: 1, Value: []byte("bc")},
					},
				},
			},
			nil,
		},
		{"combo 2",
			abnf.Concat(`[ "a" ] "abc"`,
				abnf.Optional(`[ "a" ]`, abnf.Literal("a", []byte("a"))),
				abnf.Literal("abc", []byte("abc")),
			),
			[]byte("abc"),
			abnf.Nodes{
				{
					Key:   `[ "a" ] "abc"`,
					Pos:   0,
					Value: []byte("abc"),
					Children: abnf.Nodes{
						{
							Key:   `[ "a" ]`,
							Pos:   0,
							Value: []byte{},
						},
						{Key: "abc", Pos: 0, Value: []byte("abc")},
					},
				},
			},
			nil,
		},
		{"combo 3",
			abnf.Concat(`[ "a" ] "a"`,
				abnf.Optional(`[ "a" ]`, abnf.Literal("a", []byte("a"))),
				abnf.Literal("a", []byte("a")),
			),
			[]byte("aa"),
			abnf.Nodes{
				{
					Key:   `[ "a" ] "a"`,
					Pos:   0,
					Value: []byte("aa"),
					Children: abnf.Nodes{
						{
							Key:   `[ "a" ]`,
							Pos:   0,
							Value: []byte("a"),
							Children: abnf.Nodes{
								{Key: "a", Pos: 0, Value: []byte("a")},
							},
						},
						{Key: "a", Pos: 1, Value: []byte("a")},
					},
				},
			},
			nil,
		},
		{"combo 4",
			abnf.ConcatAll(`[ "a" ] "a"`,
				abnf.Optional(`[ "a" ]`, abnf.Literal("a", []byte("a"))),
				abnf.Literal("a", []byte("a")),
			),
			[]byte("aa"),
			abnf.Nodes{
				{
					Key:   `[ "a" ] "a"`,
					Pos:   0,
					Value: []byte("aa"),
					Children: abnf.Nodes{
						{
							Key:   `[ "a" ]`,
							Pos:   0,
							Value: []byte("a"),
							Children: abnf.Nodes{
								{Key: "a", Pos: 0, Value: []byte("a")},
							},
						},
						{Key: "a", Pos: 1, Value: []byte("a")},
					},
				},
				{
					Key:   `[ "a" ] "a"`,
					Pos:   0,
					Value: []byte("a"),
					Children: abnf.Nodes{
						{Key: `[ "a" ]`, Pos: 0, Value: []byte("")},
						{Key: "a", Pos: 0, Value: []byte("a")},
					},
				},
			},
			nil,
		},
		{"combo 5",
			abnf.ConcatAll(`[ "a" ] "a"`,
				abnf.Optional(`[ "a" ]`, abnf.Literal("a", []byte("a"))),
				abnf.Literal("a", []byte("a")),
			),
			[]byte("a"),
			abnf.Nodes{
				{
					Key:   `[ "a" ] "a"`,
					Pos:   0,
					Value: []byte("a"),
					Children: abnf.Nodes{
						{Key: `[ "a" ]`, Pos: 0, Value: []byte("")},
						{Key: "a", Pos: 0, Value: []byte("a")},
					},
				},
			},
			nil,
		},
		{"combo 6",
			abnf.Repeat0Inf(`*( [ "a" ] )`, abnf.Optional(`[ "a" ]`, abnf.Literal("a", []byte("a")))),
			[]byte(""),
			abnf.Nodes{
				{
					Key:   `*( [ "a" ] )`,
					Pos:   0,
					Value: []byte(""),
				},
			},
			nil,
		},
		{"combo 7",
			abnf.Repeat0Inf(`*( [ "a" ] )`, abnf.Optional(`[ "a" ]`, abnf.Literal("a", []byte("a")))),
			[]byte("aa"),
			abnf.Nodes{
				{
					Key:   `*( [ "a" ] )`,
					Pos:   0,
					Value: []byte("aa"),
					Children: abnf.Nodes{
						{
							Key:   `[ "a" ]`,
							Pos:   0,
							Value: []byte("a"),
							Children: abnf.Nodes{
								{Key: "a", Pos: 0, Value: []byte("a")},
							},
						},
						{
							Key:   `[ "a" ]`,
							Pos:   1,
							Value: []byte("a"),
							Children: abnf.Nodes{
								{Key: "a", Pos: 1, Value: []byte("a")},
							},
						},
					},
				},
				{
					Key:   `*( [ "a" ] )`,
					Pos:   0,
					Value: []byte("a"),
					Children: abnf.Nodes{
						{
							Key:   `[ "a" ]`,
							Pos:   0,
							Value: []byte("a"),
							Children: abnf.Nodes{
								{Key: "a", Pos: 0, Value: []byte("a")},
							},
						},
						{Key: `[ "a" ]`, Pos: 1, Value: []byte("")},
					},
				},
				{
					Key:   `*( [ "a" ] )`,
					Pos:   0,
					Value: []byte("a"),
					Children: abnf.Nodes{
						{Key: `[ "a" ]`, Pos: 0, Value: []byte("")},
						{
							Key:   `[ "a" ]`,
							Pos:   0,
							Value: []byte("a"),
							Children: abnf.Nodes{
								{Key: "a", Pos: 0, Value: []byte("a")},
							},
						},
					},
				},
				{
					Key:   `*( [ "a" ] )`,
					Pos:   0,
					Value: []byte(""),
					Children: abnf.Nodes{
						{Key: `[ "a" ]`, Pos: 0, Value: []byte("")},
						{Key: `[ "a" ]`, Pos: 0, Value: []byte("")},
					},
				},
				{
					Key:   `*( [ "a" ] )`,
					Pos:   0,
					Value: []byte("a"),
					Children: abnf.Nodes{
						{
							Key:   `[ "a" ]`,
							Pos:   0,
							Value: []byte("a"),
							Children: abnf.Nodes{
								{Key: "a", Pos: 0, Value: []byte("a")},
							},
						},
					},
				},
				{
					Key:   `*( [ "a" ] )`,
					Pos:   0,
					Value: []byte(""),
					Children: abnf.Nodes{
						{Key: `[ "a" ]`, Pos: 0, Value: []byte("")},
					},
				},
				{
					Key:   `*( [ "a" ] )`,
					Pos:   0,
					Value: []byte(""),
				},
			},
			nil,
		},
		{"combo 8",
			abnf.Concat(`"a" *( "a" / "b" ) "a"`,
				abnf.Literal("a", []byte("a")),
				abnf.Repeat0Inf(`*( "a" / "b" )`,
					abnf.Alt(`"a" / "b"`,
						abnf.Literal("a", []byte("a")),
						abnf.Literal("b", []byte("b")),
					),
				),
				abnf.Literal("a", []byte("a")),
			),
			[]byte("aa"),
			abnf.Nodes{
				{
					Key:   `"a" *( "a" / "b" ) "a"`,
					Pos:   0,
					Value: []byte("aa"),
					Children: abnf.Nodes{
						{Key: "a", Pos: 0, Value: []byte("a")},
						{Key: `*( "a" / "b" )`, Pos: 1, Value: []byte("")},
						{Key: "a", Pos: 1, Value: []byte("a")},
					},
				},
			},
			nil,
		},
		{"combo 9",
			abnf.Concat(`"a" *( "a" / "b" ) "a"`,
				abnf.Literal("a", []byte("a")),
				abnf.Repeat0Inf(`*( "a" / "b" )`,
					abnf.Alt(`"a" / "b"`,
						abnf.Literal("a", []byte("a")),
						abnf.Literal("b", []byte("b")),
					),
				),
				abnf.Literal("a", []byte("a")),
			),
			[]byte("aaa"),
			abnf.Nodes{
				{
					Key:   `"a" *( "a" / "b" ) "a"`,
					Pos:   0,
					Value: []byte("aaa"),
					Children: abnf.Nodes{
						{Key: "a", Pos: 0, Value: []byte("a")},
						{
							Key:   `*( "a" / "b" )`,
							Pos:   1,
							Value: []byte("a"),
							Children: abnf.Nodes{
								{
									Key:   `"a" / "b"`,
									Pos:   1,
									Value: []byte("a"),
									Children: abnf.Nodes{
										{Key: "a", Pos: 1, Value: []byte("a")},
									},
								},
							},
						},
						{Key: "a", Pos: 2, Value: []byte("a")},
					},
				},
			},
			nil,
		},
		{"combo 10",
			abnf.Concat(`"a" *( "a" / "b" ) "a"`,
				abnf.Literal("a", []byte("a")),
				abnf.Repeat0Inf(`*( "a" / "b" )`,
					abnf.Alt(`"a" / "b"`,
						abnf.Literal("a", []byte("a")),
						abnf.Literal("b", []byte("b")),
					),
				),
				abnf.Literal("a", []byte("a")),
			),
			[]byte("aaba"),
			abnf.Nodes{
				{
					Key:   `"a" *( "a" / "b" ) "a"`,
					Pos:   0,
					Value: []byte("aaba"),
					Children: abnf.Nodes{
						{Key: "a", Pos: 0, Value: []byte("a")},
						{
							Key:   `*( "a" / "b" )`,
							Pos:   1,
							Value: []byte("ab"),
							Children: abnf.Nodes{
								{
									Key:   `"a" / "b"`,
									Pos:   1,
									Value: []byte("a"),
									Children: abnf.Nodes{
										{Key: "a", Pos: 1, Value: []byte("a")},
									},
								},
								{
									Key:   `"a" / "b"`,
									Pos:   2,
									Value: []byte("b"),
									Children: abnf.Nodes{
										{Key: "b", Pos: 2, Value: []byte("b")},
									},
								},
							},
						},
						{Key: "a", Pos: 3, Value: []byte("a")},
					},
				},
			},
			nil,
		},
		{"combo 11",
			abnf.Concat(`(*"a" / *"b") "a"`,
				abnf.Alt(`*"a" / *"b"`,
					abnf.Repeat0Inf(`*"a"`, abnf.Literal("a", []byte("a"))),
					abnf.Repeat0Inf(`*"b"`, abnf.Literal("b", []byte("b"))),
				),
				abnf.Literal("a", []byte("a")),
			),
			[]byte("a"),
			abnf.Nodes{
				{
					Key:   `(*"a" / *"b") "a"`,
					Pos:   0,
					Value: []byte("a"),
					Children: abnf.Nodes{
						{
							Key:   `*"a" / *"b"`,
							Pos:   0,
							Value: []byte(""),
							Children: abnf.Nodes{
								{Key: `*"a"`, Pos: 0, Value: []byte("")},
							},
						},
						{Key: "a", Pos: 0, Value: []byte("a")},
					},
				},
			},
			nil,
		},
		{"combo 12",
			abnf.Concat(`(*"a" / *"b") "a"`,
				abnf.Alt(`*"a" / *"b"`,
					abnf.Repeat0Inf(`*"a"`, abnf.Literal("a", []byte("a"))),
					abnf.Repeat0Inf(`*"b"`, abnf.Literal("b", []byte("b"))),
				),
				abnf.Literal("a", []byte("a")),
			),
			[]byte("aa"),
			abnf.Nodes{
				{
					Key:   `(*"a" / *"b") "a"`,
					Pos:   0,
					Value: []byte("aa"),
					Children: abnf.Nodes{
						{
							Key:   `*"a" / *"b"`,
							Pos:   0,
							Value: []byte("a"),
							Children: abnf.Nodes{
								{
									Key:   `*"a"`,
									Pos:   0,
									Value: []byte("a"),
									Children: abnf.Nodes{
										{Key: "a", Pos: 0, Value: []byte("a")},
									},
								},
							},
						},
						{Key: "a", Pos: 1, Value: []byte("a")},
					},
				},
			},
			nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotNs, gotErr := c.op(c.in, 0, nil)
			if c.wantErr == nil {
				if gotErr != nil {
					t.Fatalf("op(in, 0, nil) error = %q, want nil", gotErr)
				}
				if !cmp.Equal(gotNs, c.wantNs) {
					t.Fatalf("op(in, 0, nil) = %+v, want %+v\ndiff (-got +want):\n%v",
						gotNs, c.wantNs,
						cmp.Diff(gotNs, c.wantNs),
					)
				}
			} else {
				// fmt.Printf("%+v\n", gotErr)
				if !cmp.Equal(gotErr, c.wantErr, cmpopts.EquateErrors()) {
					t.Fatalf("op(in, 0, nil) error = %q, want %q\ndiff (-got +want):\n%v",
						gotErr, c.wantErr,
						cmp.Diff(gotErr, c.wantErr, cmpopts.EquateErrors()),
					)
				}
			}
		})
	}
}

func BenchmarkLiteral(b *testing.B) {
	op := abnf.Literal("z", []byte("z"))
	in := []byte("zzz")
	ns := make(abnf.Nodes, 0, 1)

	b.ResetTimer()
	for b.Loop() {
		var err error
		ns = ns[:0]
		ns, err = op(in, 0, ns)
		if err != nil {
			b.Errorf("operator returned error %q, want nil", err)
			continue
		}
		if len(ns) != 1 {
			b.Errorf("operator returned %d nodes, want 1", len(ns))
		}
	}
}

func BenchmarkLiteral_unicode(b *testing.B) {
	op := abnf.Literal("м", []byte("м"))
	in := []byte("мир")
	ns := make(abnf.Nodes, 0, 1)

	b.ResetTimer()
	for b.Loop() {
		var err error
		ns = ns[:0]
		ns, err = op(in, 0, ns)
		if err != nil {
			b.Errorf("operator returned error %q, want nil", err)
			continue
		}
		if len(ns) != 1 {
			b.Errorf("operator returned %d nodes, want 1", len(ns))
		}
	}
}

func BenchmarkLiteralCS(b *testing.B) {
	op := abnf.LiteralCS("Z", []byte("Z"))
	in := []byte("ZZZ")
	ns := make(abnf.Nodes, 0, 1)

	b.ResetTimer()
	for b.Loop() {
		var err error
		ns = ns[:0]
		ns, err = op(in, 0, ns)
		if err != nil {
			b.Errorf("operator returned error %q, want nil", err)
			continue
		}
		if len(ns) != 1 {
			b.Errorf("operator returned %d nodes, want 1", len(ns))
		}
	}
}

func BenchmarkRange(b *testing.B) {
	op := abnf.Range("%x61-7A", []byte{97}, []byte{122})
	in := []byte("zzz")
	ns := make(abnf.Nodes, 0, 1)

	b.ResetTimer()
	for b.Loop() {
		var err error
		ns = ns[:0]
		ns, err = op(in, 0, ns)
		if err != nil {
			b.Errorf("operator returned error %q, want nil", err)
			continue
		}
		if len(ns) != 1 {
			b.Errorf("operator returned %d nodes, want 1", len(ns))
		}
	}
}

func BenchmarkAlt(tb *testing.B) {
	op := abnf.Alt(`"a" / "b" / "c"`,
		abnf.Literal("a", []byte("a")),
		abnf.Literal("b", []byte("b")),
		abnf.Literal("c", []byte("c")),
	)
	inputs := [][]byte{
		[]byte("a"),
		[]byte("b"),
		[]byte("c"),
	}
	ns := make(abnf.Nodes, 0, 1)

	for _, in := range inputs {
		tb.Run(string(in), func(b *testing.B) {
			b.ResetTimer()
			for b.Loop() {
				var err error
				ns, err = op(in, 0, ns[:0])
				if err != nil {
					b.Fatalf("operator returned error %q, want nil", err)
				}
				if len(ns) == 0 {
					b.Fatal("operator returned 0 nodes, want at least 1")
				}
			}
		})
	}
}

func BenchmarkConcat(b *testing.B) {
	op := abnf.Concat(`"ab" "c"`, abnf.Literal("ab", []byte("ab")), abnf.Literal("c", []byte("c")))
	in := []byte("abc")
	ns := make(abnf.Nodes, 0, 1)

	b.ResetTimer()
	for b.Loop() {
		var err error
		ns, err = op(in, 0, ns[:0])
		if err != nil {
			b.Errorf("operator returned error %q, want nil", err)
			continue
		}
		if len(ns) == 0 {
			b.Error("operator returned 0 nodes, want at least 1")
		}
	}
}

func BenchmarkRepeat0Inf(b *testing.B) {
	op := abnf.Repeat0Inf(`*"a"`, abnf.Literal("a", []byte("a")))
	inputs := [][]byte{[]byte(""), []byte("a"), []byte("aaa")}
	ns := make(abnf.Nodes, 0, 9)

	b.ResetTimer()
	for _, in := range inputs {
		b.Run(string(in), func(b *testing.B) {
			b.ResetTimer()
			for b.Loop() {
				var err error
				ns, err = op(in, 0, ns[:0])
				if err != nil {
					b.Fatalf("operator returned error %q, want nil", err)
				}
				if len(ns) == 0 {
					b.Fatal("operator returned 0 nodes, want at least 1")
				}
			}
		})
	}
}
