package abnf_gen_test

import (
	"bytes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/ghettovoice/abnf"
	"github.com/ghettovoice/abnf/pkg/abnf_core"
	"github.com/ghettovoice/abnf/pkg/abnf_gen"
)

var _ = Describe("ParserGenerator", func() {
	var g *abnf_gen.ParserGenerator

	BeforeEach(func() {
		g = &abnf_gen.ParserGenerator{
			External: map[string]abnf_gen.ExternalRule{
				"bit": {
					IsOperator: true,
					Operator:   abnf_core.BIT,
				},
				"alpha": {
					Factory: func() abnf.Operator { return abnf_core.ALPHA },
				},
			},
		}

		b1 := bytes.NewBuffer([]byte(
			"r1 = r2 / \"2\"\n" +
				"r2 = bit / alpha\n",
		))
		Expect(g.ReadFrom(b1)).Error().Should(Succeed())
	})

	It("should build operators", func() {
		op := g.Operators()["r1"]
		Expect(op([]byte("0"), nil)).Should(Equal(abnf.Nodes{
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
		}))
	})

	It("should build factories", func() {
		factr := g.Factories()
		op := factr["r1"]()
		Expect(op([]byte("0"), nil)).Should(Equal(abnf.Nodes{
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
		}))
	})

	It("should extend rule", func() {
		op := g.Operators()["r1"]
		Expect(op([]byte("3"), nil)).Should(BeEmpty())

		Expect(g.ReadFrom(bytes.NewBuffer([]byte("r1 =/ \"3\"")))).Error().Should(Succeed())

		op = g.Operators()["r1"]
		Expect(op([]byte("3"), nil)).Should(Equal(abnf.Nodes{
			{
				Key:   "r1",
				Value: []byte("3"),
				Children: abnf.Nodes{
					{Key: "\"3\"", Value: []byte("3")},
				},
			},
		}))
	})
})
