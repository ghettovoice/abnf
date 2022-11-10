package abnf_def_test

import (
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/ghettovoice/abnf"
	"github.com/ghettovoice/abnf/pkg/abnf_def"
)

var _ = Describe("Definition", func() {
	Describe("Rule", func() {
		var entries []TableEntry
		for _, el := range []struct{ in, exp string }{
			{"BIT = \"0\" / \"1\"\r\n", "BIT = \"0\" / \"1\"\r\n"},
			{"ALPHA  = %x41-5A / %x61-7A ; A-Z / a-z\r\n", "ALPHA  = %x41-5A / %x61-7A ; A-Z / a-z\r\n"},
			{"DQUOTE = %x22\r\n       ; \" (Double Quote)\r\n", "DQUOTE = %x22\r\n"},
			{"WSP    = SP / HTAB\r\n", "WSP    = SP / HTAB\r\n"},
			{
				"bin-val = \"b\" 1*BIT\n\t\t\t\t[ 1*(\".\" 1*BIT) / (\"-\" 1*BIT) ]\n",
				"bin-val = \"b\" 1*BIT\n\t\t\t\t[ 1*(\".\" 1*BIT) / (\"-\" 1*BIT) ]\n",
			},
		} {
			entries = append(entries, Entry(el.in, el.in, el.exp))
		}

		DescribeTable("",
			func(in, expect string) {
				n := abnf_def.Rule([]byte(in), nil).Best()
				Expect(n.String()).Should(Equal(expect))
			},
			entries,
		)
	})

	Describe("Rulelist", func() {
		DescribeTable("",
			func(path string) {
				in, err := os.ReadFile(path)
				Expect(err).ShouldNot(HaveOccurred())

				n := abnf_def.Rulelist(in, nil).Best()
				Expect(n.String()).Should(Equal(string(in)))
			},
			Entry("rules.abnf", "../abnf_core/rules.abnf"),
			Entry("rules.abnf", "./rules.abnf"),
		)
	})
})

func BenchmarkRulelist(b *testing.B) {
	in, err := os.ReadFile("./rules.abnf")
	if err != nil {
		b.Fatalf("read ABNF file: %s", err)
	}
	ns := make(abnf.Nodes, 0, 40)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(abnf_def.Rulelist(in, ns[:0])) == 0 {
			b.Error("expected result, but got nothing")
		}
	}
}
