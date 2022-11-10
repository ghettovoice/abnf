package abnf_gen_test

import (
	"bytes"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/ghettovoice/abnf/pkg/abnf_gen"
)

var _ = Describe("CodeGenerator", func() {
	DescribeTable("",
		func(abnfPath, expPath string, gen *abnf_gen.CodeGenerator) {
			raw, err := os.ReadFile(abnfPath)
			Expect(err).ShouldNot(HaveOccurred())

			src := bytes.NewBuffer(raw)
			Expect(gen.ReadFrom(src)).Error().ShouldNot(HaveOccurred())

			var dst bytes.Buffer
			Expect(gen.WriteTo(&dst)).Error().ShouldNot(HaveOccurred())

			exp, err := os.ReadFile(expPath)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(dst.String()).Should(Equal(string(exp)))
		},
		Entry("rules.abnf",
			"../abnf_core/rules.abnf",
			"../abnf_core/rules.go",
			&abnf_gen.CodeGenerator{
				PackageName: "abnf_core",
				AsOperators: true,
			},
		),
		Entry("rules.abnf",
			"../abnf_def/rules.abnf",
			"../abnf_def/rules.go",
			&abnf_gen.CodeGenerator{
				PackageName: "abnf_def",
				AsOperators: true,
				External: map[string]abnf_gen.ExternalRule{
					"CRLF": {
						PackagePath: "github.com/ghettovoice/abnf/pkg/abnf_core",
						PackageName: "abnf_core",
						IsOperator:  true,
					},
					"WSP": {
						PackagePath: "github.com/ghettovoice/abnf/pkg/abnf_core",
						PackageName: "abnf_core",
						IsOperator:  true,
					},
					"BIT": {
						PackagePath: "github.com/ghettovoice/abnf/pkg/abnf_core",
						PackageName: "abnf_core",
						IsOperator:  true,
					},
					"VCHAR": {
						PackagePath: "github.com/ghettovoice/abnf/pkg/abnf_core",
						PackageName: "abnf_core",
						IsOperator:  true,
					},
					"DIGIT": {
						PackagePath: "github.com/ghettovoice/abnf/pkg/abnf_core",
						PackageName: "abnf_core",
						IsOperator:  true,
					},
					"HEXDIG": {
						PackagePath: "github.com/ghettovoice/abnf/pkg/abnf_core",
						PackageName: "abnf_core",
						IsOperator:  true,
					},
					"DQUOTE": {
						PackagePath: "github.com/ghettovoice/abnf/pkg/abnf_core",
						PackageName: "abnf_core",
						IsOperator:  true,
					},
					"ALPHA": {
						PackagePath: "github.com/ghettovoice/abnf/pkg/abnf_core",
						PackageName: "abnf_core",
						IsOperator:  true,
					},
				},
			},
		),
	)
})
