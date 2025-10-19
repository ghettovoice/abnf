package abnf_gen_test

import (
	"bytes"
	"testing"

	"github.com/ghettovoice/abnf"
	"github.com/ghettovoice/abnf/pkg/abnf_core"
	"github.com/ghettovoice/abnf/pkg/abnf_gen"
	"github.com/google/go-cmp/cmp"
)

func TestParserGenerator_Operators(t *testing.T) {
	g := &abnf_gen.ParserGenerator{
		External: map[string]abnf_gen.ExternalRule{
			"bit": {
				Operator: abnf_core.Operators().BIT,
			},
			"alpha": {
				Operator: abnf_core.Operators().ALPHA,
			},
		},
	}
	src := bytes.NewBuffer([]byte(
		"r1 = r2 / \"2\"\n" +
			"r2 = bit / alpha\n",
	))

	if _, err := g.ReadFrom(src); err != nil {
		t.Fatalf("g.ReadFrom(src) error = %v, want nil", err)
	}

	op := g.Operators()["r1"]
	if op == nil {
		t.Fatalf("g.Operators()[\"r1\"] = nil, want not nil")
	}

	ns := abnf.NewNodes()
	defer ns.Free()

	if err := op([]byte("0"), 0, &ns); err != nil {
		t.Fatalf("op([]byte(\"0\"), 0, nil) error = %v, want nil", err)
	}

	want := abnf.Nodes{
		{
			Key:   "r1",
			Value: []byte("0"),
			Children: abnf.Nodes{
				{
					Key:   "r2",
					Value: []byte("0"),
					Children: abnf.Nodes{
						{
							Key:   "BIT",
							Value: []byte("0"),
							Children: abnf.Nodes{
								{Key: "\"0\"", Value: []byte("0")},
							},
						},
					},
				},
			},
		},
	}
	if !cmp.Equal(ns, want) {
		t.Fatalf("op([]byte(\"0\"), 0, nil) = %+v, want %+v\ndiff (-got +want):\n%v", ns, want, cmp.Diff(ns, want))
	}
}
