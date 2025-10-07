package abnf_core_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/ghettovoice/abnf"
	"github.com/ghettovoice/abnf/pkg/abnf_core"
)

func TestRulesDescr_ALPHA(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		wantNs  abnf.Nodes
		wantErr error
	}{
		{"lc letter",
			[]byte("a"),
			abnf.Nodes{
				{
					Key:   "ALPHA",
					Value: []byte("a"),
					Children: abnf.Nodes{
						{Key: "%x61-7A", Value: []byte("a")},
					},
				},
			},
			nil,
		},
		{"uc letter",
			[]byte("Z"),
			abnf.Nodes{
				{
					Key:   "ALPHA",
					Value: []byte("Z"),
					Children: abnf.Nodes{
						{Key: "%x41-5A", Value: []byte("Z")},
					},
				},
			},
			nil,
		},
		{"not letter",
			[]byte("0"),
			nil,
			abnf.ErrNotMatched,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotNs, gotErr := abnf_core.Rules().ALPHA(c.in, nil)
			if c.wantErr == nil {
				if gotErr != nil {
					t.Fatalf("abnf_core.Rules().ALPHA(%q, nil) error = %v, want nil", c.in, gotErr)
				}
				if !cmp.Equal(gotNs, c.wantNs) {
					t.Fatalf("abnf_core.Rules().ALPHA(%q, nil) = %v, want %v\ndiff (-got +want):\n%v",
						c.in, gotNs, c.wantNs,
						cmp.Diff(gotNs, c.wantNs),
					)
				}
			} else {
				// fmt.Printf("%+v\n", gotErr)
				if !cmp.Equal(gotErr, c.wantErr, cmpopts.EquateErrors()) {
					t.Fatalf("abnf_core.Rules().ALPHA(%q, nil) error = %v, want %q\ndiff (-got +want):\n%v",
						c.in, gotErr, c.wantErr,
						cmp.Diff(gotErr, c.wantErr, cmpopts.EquateErrors()),
					)
				}
			}
		})
	}
}

func TestRulesDescr_BIT(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		wantNs  abnf.Nodes
		wantErr error
	}{
		{"0",
			[]byte("0"),
			abnf.Nodes{
				{
					Key:   "BIT",
					Value: []byte("0"),
					Children: abnf.Nodes{
						{Key: "\"0\"", Value: []byte("0")},
					},
				},
			},
			nil,
		},
		{"1",
			[]byte("1"),
			abnf.Nodes{
				{
					Key:   "BIT",
					Value: []byte("1"),
					Children: abnf.Nodes{
						{Key: "\"1\"", Value: []byte("1")},
					},
				},
			},
			nil,
		},
		{"not bit",
			[]byte("2"),
			nil,
			abnf.ErrNotMatched,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotNs, gotErr := abnf_core.Rules().BIT(c.in, nil)
			if c.wantErr == nil {
				if gotErr != nil {
					t.Fatalf("abnf_core.Rules().BIT(%q, nil) error = %v, want nil", c.in, gotErr)
				}
				if !cmp.Equal(gotNs, c.wantNs) {
					t.Fatalf("abnf_core.Rules().BIT(%q, nil) = %v, want %v\ndiff (-got +want):\n%v",
						c.in, gotNs, c.wantNs,
						cmp.Diff(gotNs, c.wantNs),
					)
				}
			} else {
				// fmt.Printf("%+v\n", gotErr)
				if !cmp.Equal(gotErr, c.wantErr, cmpopts.EquateErrors()) {
					t.Fatalf("abnf_core.Rules().BIT(%q, nil) error = %v, want %q\ndiff (-got +want):\n%v",
						c.in, gotErr, c.wantErr,
						cmp.Diff(gotErr, c.wantErr, cmpopts.EquateErrors()),
					)
				}
			}
		})
	}
}

func TestRulesDescr_CHAR(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		wantNs  abnf.Nodes
		wantErr error
	}{
		{"~",
			[]byte("~"),
			abnf.Nodes{
				{Key: "CHAR", Value: []byte("~")},
			},
			nil,
		},
		{"a",
			[]byte("a"),
			abnf.Nodes{
				{Key: "CHAR", Value: []byte("a")},
			},
			nil,
		},
		{"0",
			[]byte("0"),
			abnf.Nodes{
				{Key: "CHAR", Value: []byte("0")},
			},
			nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotNs, gotErr := abnf_core.Rules().CHAR(c.in, nil)
			if c.wantErr == nil {
				if gotErr != nil {
					t.Fatalf("abnf_core.Rules().CHAR(%q, nil) error = %v, want nil", c.in, gotErr)
				}
				if !cmp.Equal(gotNs, c.wantNs) {
					t.Fatalf("abnf_core.Rules().CHAR(%q, nil) = %v, want %v\ndiff (-got +want):\n%v",
						c.in, gotNs, c.wantNs,
						cmp.Diff(gotNs, c.wantNs),
					)
				}
			} else {
				// fmt.Printf("%+v\n", gotErr)
				if !cmp.Equal(gotErr, c.wantErr, cmpopts.EquateErrors()) {
					t.Fatalf("abnf_core.Rules().CHAR(%q, nil) error = %v, want %q\ndiff (-got +want):\n%v",
						c.in, gotErr, c.wantErr,
						cmp.Diff(gotErr, c.wantErr, cmpopts.EquateErrors()),
					)
				}
			}
		})
	}
}

func TestRulesDescr_CRLF(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		wantNs  abnf.Nodes
		wantErr error
	}{
		{"crlf",
			[]byte("\r\n"),
			abnf.Nodes{
				{
					Key:   "CRLF",
					Value: []byte("\r\n"),
					Children: abnf.Nodes{
						{
							Key:   "CR LF",
							Value: []byte("\r\n"),
							Children: abnf.Nodes{
								{Key: "CR", Pos: 0, Value: []byte("\r")},
								{Key: "LF", Pos: 1, Value: []byte("\n")},
							},
						},
					},
				},
			},
			nil,
		},
		{"lf",
			[]byte("\n"),
			abnf.Nodes{
				{
					Key:   "CRLF",
					Value: []byte("\n"),
					Children: abnf.Nodes{
						{Key: "LF", Value: []byte("\n")},
					},
				},
			},
			nil,
		},
		{"not crlf",
			[]byte("\b"),
			nil,
			abnf.ErrNotMatched,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotNs, gotErr := abnf_core.Rules().CRLF(c.in, nil)
			if c.wantErr == nil {
				if gotErr != nil {
					t.Fatalf("abnf_core.Rules().CRLF(%q, nil) error = %v, want nil", c.in, gotErr)
				}
				if !cmp.Equal(gotNs, c.wantNs) {
					t.Fatalf("abnf_core.Rules().CRLF(%q, nil) = %v, want %v\ndiff (-got +want):\n%v",
						c.in, gotNs, c.wantNs,
						cmp.Diff(gotNs, c.wantNs),
					)
				}
			} else {
				// fmt.Printf("%+v\n", gotErr)
				if !cmp.Equal(gotErr, c.wantErr, cmpopts.EquateErrors()) {
					t.Fatalf("abnf_core.Rules().CRLF(%q, nil) error = %v, want %q\ndiff (-got +want):\n%v",
						c.in, gotErr, c.wantErr,
						cmp.Diff(gotErr, c.wantErr, cmpopts.EquateErrors()),
					)
				}
			}
		})
	}
}

func TestRulesDescr_CTL(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		wantNs  abnf.Nodes
		wantErr error
	}{
		{"ctl",
			[]byte("\u001B"),
			abnf.Nodes{
				{
					Key:   "CTL",
					Value: []byte("\u001B"),
					Children: abnf.Nodes{
						{Key: "%x00-1F", Value: []byte("\u001B")},
					},
				},
			},
			nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotNs, gotErr := abnf_core.Rules().CTL(c.in, nil)
			if c.wantErr == nil {
				if gotErr != nil {
					t.Fatalf("abnf_core.Rules().CTL(%q, nil) error = %v, want nil", c.in, gotErr)
				}
				if !cmp.Equal(gotNs, c.wantNs) {
					t.Fatalf("abnf_core.Rules().CTL(%q, nil) = %v, want %v\ndiff (-got +want):\n%v",
						c.in, gotNs, c.wantNs,
						cmp.Diff(gotNs, c.wantNs),
					)
				}
			} else {
				// fmt.Printf("%+v\n", gotErr)
				if !cmp.Equal(gotErr, c.wantErr, cmpopts.EquateErrors()) {
					t.Fatalf("abnf_core.Rules().CTL(%q, nil) error = %v, want %q\ndiff (-got +want):\n%v",
						c.in, gotErr, c.wantErr,
						cmp.Diff(gotErr, c.wantErr, cmpopts.EquateErrors()),
					)
				}
			}
		})
	}
}

func TestRulesDescr_DIGIT(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		wantNs  abnf.Nodes
		wantErr error
	}{
		{"digit 0",
			[]byte("0"),
			abnf.Nodes{
				{
					Key:   "DIGIT",
					Value: []byte("0"),
				},
			},
			nil,
		},
		{"digit 9",
			[]byte("9"),
			abnf.Nodes{
				{
					Key:   "DIGIT",
					Value: []byte("9"),
				},
			},
			nil,
		},
		{"not digit",
			[]byte("a"),
			nil,
			abnf.ErrNotMatched,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotNs, gotErr := abnf_core.Rules().DIGIT(c.in, nil)
			if c.wantErr == nil {
				if gotErr != nil {
					t.Fatalf("abnf_core.Rules().DIGIT(%q, nil) error = %v, want nil", c.in, gotErr)
				}
				if !cmp.Equal(gotNs, c.wantNs) {
					t.Fatalf("abnf_core.Rules().DIGIT(%q, nil) = %v, want %v\ndiff (-got +want):\n%v",
						c.in, gotNs, c.wantNs,
						cmp.Diff(gotNs, c.wantNs),
					)
				}
			} else {
				// fmt.Printf("%+v\n", gotErr)
				if !cmp.Equal(gotErr, c.wantErr, cmpopts.EquateErrors()) {
					t.Fatalf("abnf_core.Rules().DIGIT(%q, nil) error = %v, want %q\ndiff (-got +want):\n%v",
						c.in, gotErr, c.wantErr,
						cmp.Diff(gotErr, c.wantErr, cmpopts.EquateErrors()),
					)
				}
			}
		})
	}
}

func TestRulesDescr_DQUOTE(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		wantNs  abnf.Nodes
		wantErr error
	}{
		{"double quote",
			[]byte("\""),
			abnf.Nodes{
				{
					Key:   "DQUOTE",
					Value: []byte("\""),
				},
			},
			nil,
		},
		{"not double quote",
			[]byte("a"),
			nil,
			abnf.ErrNotMatched,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotNs, gotErr := abnf_core.Rules().DQUOTE(c.in, nil)
			if c.wantErr == nil {
				if gotErr != nil {
					t.Fatalf("abnf_core.Rules().DQUOTE(%q, nil) error = %v, want nil", c.in, gotErr)
				}
				if !cmp.Equal(gotNs, c.wantNs) {
					t.Fatalf("abnf_core.Rules().DQUOTE(%q, nil) = %v, want %v\ndiff (-got +want):\n%v",
						c.in, gotNs, c.wantNs,
						cmp.Diff(gotNs, c.wantNs),
					)
				}
			} else {
				// fmt.Printf("%+v\n", gotErr)
				if !cmp.Equal(gotErr, c.wantErr, cmpopts.EquateErrors()) {
					t.Fatalf("abnf_core.Rules().DQUOTE(%q, nil) error = %v, want %q\ndiff (-got +want):\n%v",
						c.in, gotErr, c.wantErr,
						cmp.Diff(gotErr, c.wantErr, cmpopts.EquateErrors()),
					)
				}
			}
		})
	}
}

func TestRulesDescr_HEXDIG(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		wantNs  abnf.Nodes
		wantErr error
	}{
		{"hexdig 7",
			[]byte("7"),
			abnf.Nodes{
				{
					Key:   "HEXDIG",
					Value: []byte("7"),
					Children: abnf.Nodes{
						{Key: "DIGIT", Value: []byte("7")},
					},
				},
			},
			nil,
		},
		{"hexdig A",
			[]byte("A"),
			abnf.Nodes{
				{
					Key:   "HEXDIG",
					Value: []byte("A"),
					Children: abnf.Nodes{
						{Key: "\"A\"", Value: []byte("A")},
					},
				},
			},
			nil,
		},
		{"hexdig a",
			[]byte("a"),
			abnf.Nodes{
				{
					Key:   "HEXDIG",
					Value: []byte("a"),
					Children: abnf.Nodes{
						{Key: "\"A\"", Value: []byte("a")},
					},
				},
			},
			nil,
		},
		{"not hexdig",
			[]byte("z"),
			nil,
			abnf.ErrNotMatched,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotNs, gotErr := abnf_core.Rules().HEXDIG(c.in, nil)
			if c.wantErr == nil {
				if gotErr != nil {
					t.Fatalf("abnf_core.Rules().HEXDIG(%q, nil) error = %v, want nil", c.in, gotErr)
				}
				if !cmp.Equal(gotNs, c.wantNs) {
					t.Fatalf("abnf_core.Rules().HEXDIG(%q, nil) = %v, want %v\ndiff (-got +want):\n%v",
						c.in, gotNs, c.wantNs,
						cmp.Diff(gotNs, c.wantNs),
					)
				}
			} else {
				// fmt.Printf("%+v\n", gotErr)
				if !cmp.Equal(gotErr, c.wantErr, cmpopts.EquateErrors()) {
					t.Fatalf("abnf_core.Rules().HEXDIG(%q, nil) error = %v, want %q\ndiff (-got +want):\n%v",
						c.in, gotErr, c.wantErr,
						cmp.Diff(gotErr, c.wantErr, cmpopts.EquateErrors()),
					)
				}
			}
		})
	}
}

func TestRulesDescr_HTAB(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		wantNs  abnf.Nodes
		wantErr error
	}{
		{"htab",
			[]byte("\t"),
			abnf.Nodes{
				{
					Key:   "HTAB",
					Value: []byte("\t"),
				},
			},
			nil,
		},
		{"not htab",
			[]byte("z"),
			nil,
			abnf.ErrNotMatched,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotNs, gotErr := abnf_core.Rules().HTAB(c.in, nil)
			if c.wantErr == nil {
				if gotErr != nil {
					t.Fatalf("abnf_core.Rules().HTAB(%q, nil) error = %v, want nil", c.in, gotErr)
				}
				if !cmp.Equal(gotNs, c.wantNs) {
					t.Fatalf("abnf_core.Rules().HTAB(%q, nil) = %v, want %v\ndiff (-got +want):\n%v",
						c.in, gotNs, c.wantNs,
						cmp.Diff(gotNs, c.wantNs),
					)
				}
			} else {
				// fmt.Printf("%+v\n", gotErr)
				if !cmp.Equal(gotErr, c.wantErr, cmpopts.EquateErrors()) {
					t.Fatalf("abnf_core.Rules().HTAB(%q, nil) error = %v, want %q\ndiff (-got +want):\n%v",
						c.in, gotErr, c.wantErr,
						cmp.Diff(gotErr, c.wantErr, cmpopts.EquateErrors()),
					)
				}
			}
		})
	}
}

func TestRulesDescr_LWSP(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		wantNs  abnf.Nodes
		wantErr error
	}{
		{"space",
			[]byte(" "),
			abnf.Nodes{
				{
					Key:   "LWSP",
					Value: []byte(" "),
					Children: abnf.Nodes{
						{
							Key:   "WSP / CRLF WSP",
							Value: []byte(" "),
							Children: abnf.Nodes{
								{
									Key:   "WSP",
									Value: []byte(" "),
									Children: abnf.Nodes{
										{Key: "SP", Value: []byte(" ")},
									},
								},
							},
						},
					},
				},
				{Key: "LWSP", Value: []byte("")},
			},
			nil,
		},
		{"crlf space",
			[]byte("\n "),
			abnf.Nodes{
				{
					Key:   "LWSP",
					Value: []byte("\n "),
					Children: abnf.Nodes{
						{
							Key:   "WSP / CRLF WSP",
							Value: []byte("\n "),
							Children: abnf.Nodes{
								{
									Key:   "CRLF WSP",
									Value: []byte("\n "),
									Children: abnf.Nodes{
										{
											Key:   "CRLF",
											Value: []byte("\n"),
											Children: abnf.Nodes{
												{Key: "LF", Value: []byte("\n")},
											},
										},
										{
											Key:   "WSP",
											Pos:   1,
											Value: []byte(" "),
											Children: abnf.Nodes{
												{Key: "SP", Pos: 1, Value: []byte(" ")},
											},
										},
									},
								},
							},
						},
					},
				},
				{Key: "LWSP", Value: []byte("")},
			},
			nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotNs, gotErr := abnf_core.Rules().LWSP(c.in, nil)
			if c.wantErr == nil {
				if gotErr != nil {
					t.Fatalf("abnf_core.Rules().LWSP(%q, nil) error = %v, want nil", c.in, gotErr)
				}
				if !cmp.Equal(gotNs, c.wantNs) {
					t.Fatalf("abnf_core.Rules().LWSP(%q, nil) = %v, want %v\ndiff (-got +want):\n%v",
						c.in, gotNs, c.wantNs,
						cmp.Diff(gotNs, c.wantNs),
					)
				}
			} else {
				// fmt.Printf("%+v\n", gotErr)
				if !cmp.Equal(gotErr, c.wantErr, cmpopts.EquateErrors()) {
					t.Fatalf("abnf_core.Rules().LWSP(%q, nil) error = %v, want %q\ndiff (-got +want):\n%v",
						c.in, gotErr, c.wantErr,
						cmp.Diff(gotErr, c.wantErr, cmpopts.EquateErrors()),
					)
				}
			}
		})
	}
}

func TestRulesDescr_OCTET(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		wantNs  abnf.Nodes
		wantErr error
	}{
		{"o",
			[]byte("o"),
			abnf.Nodes{
				{Key: "OCTET", Value: []byte("o")},
			},
			nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotNs, gotErr := abnf_core.Rules().OCTET(c.in, nil)
			if c.wantErr == nil {
				if gotErr != nil {
					t.Fatalf("abnf_core.Rules().OCTET(%q, nil) error = %v, want nil", c.in, gotErr)
				}
				if !cmp.Equal(gotNs, c.wantNs) {
					t.Fatalf("abnf_core.Rules().OCTET(%q, nil) = %v, want %v\ndiff (-got +want):\n%v",
						c.in, gotNs, c.wantNs,
						cmp.Diff(gotNs, c.wantNs),
					)
				}
			} else {
				// fmt.Printf("%+v\n", gotErr)
				if !cmp.Equal(gotErr, c.wantErr, cmpopts.EquateErrors()) {
					t.Fatalf("abnf_core.Rules().OCTET(%q, nil) error = %v, want %q\ndiff (-got +want):\n%v",
						c.in, gotErr, c.wantErr,
						cmp.Diff(gotErr, c.wantErr, cmpopts.EquateErrors()),
					)
				}
			}
		})
	}
}

func TestRulesDescr_VCHAR(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		wantNs  abnf.Nodes
		wantErr error
	}{
		{"vchar",
			[]byte("`"),
			abnf.Nodes{
				{Key: "VCHAR", Value: []byte("`")},
			},
			nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotNs, gotErr := abnf_core.Rules().VCHAR(c.in, nil)
			if c.wantErr == nil {
				if gotErr != nil {
					t.Fatalf("abnf_core.Rules().VCHAR(%q, nil) error = %v, want nil", c.in, gotErr)
				}
				if !cmp.Equal(gotNs, c.wantNs) {
					t.Fatalf("abnf_core.Rules().VCHAR(%q, nil) = %v, want %v\ndiff (-got +want):\n%v",
						c.in, gotNs, c.wantNs,
						cmp.Diff(gotNs, c.wantNs),
					)
				}
			} else {
				// fmt.Printf("%+v\n", gotErr)
				if !cmp.Equal(gotErr, c.wantErr, cmpopts.EquateErrors()) {
					t.Fatalf("abnf_core.Rules().VCHAR(%q, nil) error = %v, want %q\ndiff (-got +want):\n%v",
						c.in, gotErr, c.wantErr,
						cmp.Diff(gotErr, c.wantErr, cmpopts.EquateErrors()),
					)
				}
			}
		})
	}
}

func TestRulesDescr_WSP(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		wantNs  abnf.Nodes
		wantErr error
	}{
		{"space",
			[]byte(" "),
			abnf.Nodes{
				{
					Key:   "WSP",
					Value: []byte(" "),
					Children: abnf.Nodes{
						{Key: "SP", Value: []byte(" ")},
					},
				},
			},
			nil,
		},
		{"htab",
			[]byte("\t"),
			abnf.Nodes{
				{
					Key:   "WSP",
					Value: []byte("\t"),
					Children: abnf.Nodes{
						{Key: "HTAB", Value: []byte("\t")},
					},
				},
			},
			nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotNs, gotErr := abnf_core.Rules().WSP(c.in, nil)
			if c.wantErr == nil {
				if gotErr != nil {
					t.Fatalf("abnf_core.Rules().WSP(%q, nil) error = %v, want nil", c.in, gotErr)
				}
				if !cmp.Equal(gotNs, c.wantNs) {
					t.Fatalf("abnf_core.Rules().WSP(%q, nil) = %v, want %v\ndiff (-got +want):\n%v",
						c.in, gotNs, c.wantNs,
						cmp.Diff(gotNs, c.wantNs),
					)
				}
			} else {
				// fmt.Printf("%+v\n", gotErr)
				if !cmp.Equal(gotErr, c.wantErr, cmpopts.EquateErrors()) {
					t.Fatalf("abnf_core.Rules().WSP(%q, nil) error = %v, want %q\ndiff (-got +want):\n%v",
						c.in, gotErr, c.wantErr,
						cmp.Diff(gotErr, c.wantErr, cmpopts.EquateErrors()),
					)
				}
			}
		})
	}
}
