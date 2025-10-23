package abnf_def_test

import (
	"os"
	"testing"

	"github.com/ghettovoice/abnf"
	"github.com/ghettovoice/abnf/pkg/abnf_def"
)

func TestRulesDescr_Rule(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"rule 1", "BIT = \"0\" / \"1\"\r\n", "BIT = \"0\" / \"1\"\r\n"},
		{"rule 2", "ALPHA  = %x41-5A / %x61-7A ; A-Z / a-z\r\n", "ALPHA  = %x41-5A / %x61-7A ; A-Z / a-z\r\n"},
		{"rule 3", "DQUOTE = %x22\r\n       ; \" (Double Quote)\r\n", "DQUOTE = %x22\r\n"},
		{"rule 4", "WSP    = SP / HTAB\r\n", "WSP    = SP / HTAB\r\n"},
		{"rule 5",
			"bin-val = \"b\" 1*BIT\n\t\t\t\t[ 1*(\".\" 1*BIT) / (\"-\" 1*BIT) ]\n",
			"bin-val = \"b\" 1*BIT\n\t\t\t\t[ 1*(\".\" 1*BIT) / (\"-\" 1*BIT) ]\n",
		},
	}

	ns := abnf.NewNodes()
	defer ns.Free()

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ns.Clear()
			if err := abnf_def.Rules().Rule([]byte(c.in), &ns); err != nil {
				t.Fatalf("abnf_def.Rules().Rule(in, ns) error = %v, want nil", err)
			}

			if got := ns.Best().String(); got != c.want {
				t.Fatalf("abnf_def.Rules().Rule(in, ns) = %s, want %s", got, c.want)
			}
		})
	}
}

func TestRulesDescr_Rulelist(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"core", "../abnf_core/rules.abnf"},
		{"def", "./rules.abnf"},
	}

	ns := abnf.NewNodes()
	defer ns.Free()

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in, err := os.ReadFile(c.in)
			if err != nil {
				t.Fatalf("os.ReadFile() error = %v, want nil", err)
			}

			ns.Clear()
			if err := abnf_def.Rules().Rulelist(in, &ns); err != nil {
				t.Fatalf("abnf_def.Rules().Rulelist(in, nil) error = %v, want nil", err)
			}

			if got, want := ns.Best().String(), string(in); got != want {
				t.Fatalf("abnf_def.Rules().Rulelist(in, nil) = %v, want %v", got, want)
			}
		})
	}
}

func BenchmarkRulesDescr_Rulelist(b *testing.B) {
	abnf.EnableNodeCache(0)
	defer abnf.DisableNodeCache()

	in, err := os.ReadFile("./rules.abnf")
	if err != nil {
		b.Fatalf("read ABNF file: %s", err)
	}

	ns := abnf.NewNodes()
	defer ns.Free()

	b.ResetTimer()
	for b.Loop() {
		ns.Clear()
		if err := abnf_def.Rules().Rulelist(in, &ns); err != nil {
			b.Errorf("abnf_def.Rules().Rulelist(in, ns) error = %v, want nil", err)
			continue
		}
		if len(ns) == 0 {
			b.Errorf("abnf_def.Rules().Rulelist(in, ns) = %+v, want not empty", ns)
			continue
		}
	}
}
