package abnf_core_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/ghettovoice/abnf"
	"github.com/ghettovoice/abnf/pkg/abnf_core"
)

var _ = Describe("Core rules", func() {
	assertFn := func(p abnf.Operator) func([]byte, abnf.Nodes) {
		return func(in []byte, expect abnf.Nodes) {
			Expect(p(in, nil)).Should(Equal(expect))
		}
	}

	Describe("ALPHA", func() {
		DescribeTable("", assertFn(abnf_core.ALPHA),
			Entry("a", []byte("a"),
				abnf.Nodes{
					{
						Key:   "ALPHA",
						Value: []byte("a"),
						Children: abnf.Nodes{
							{Key: "%x61-7A", Value: []byte("a")},
						},
					},
				},
			),
			Entry("Z", []byte("Z"),
				abnf.Nodes{
					{
						Key:   "ALPHA",
						Value: []byte("Z"),
						Children: abnf.Nodes{
							{Key: "%x41-5A", Value: []byte("Z")},
						},
					},
				},
			),
			Entry("0", []byte("0"), nil),
		)
	})

	Describe("BIT", func() {
		DescribeTable("", assertFn(abnf_core.BIT),
			Entry("0", []byte("0"),
				abnf.Nodes{
					{
						Key:   "BIT",
						Value: []byte("0"),
						Children: abnf.Nodes{
							{Key: "\"0\"", Value: []byte("0")},
						},
					},
				},
			),
			Entry("1", []byte("1"),
				abnf.Nodes{
					{
						Key:   "BIT",
						Value: []byte("1"),
						Children: abnf.Nodes{
							{Key: "\"1\"", Value: []byte("1")},
						},
					},
				},
			),
			Entry("2", []byte("2"), nil),
		)
	})

	Describe("CHAR", func() {
		DescribeTable("", assertFn(abnf_core.CHAR),
			Entry("~", []byte("~"),
				abnf.Nodes{
					{Key: "CHAR", Value: []byte("~")},
				},
			),
			Entry("a", []byte("a"),
				abnf.Nodes{
					{Key: "CHAR", Value: []byte("a")},
				},
			),
		)
	})

	Describe("CRLF", func() {
		DescribeTable("", assertFn(abnf_core.CRLF),
			Entry("\\r\\n", []byte("\r\n"),
				abnf.Nodes{
					{
						Key:   "CRLF",
						Value: []byte("\r\n"),
						Children: abnf.Nodes{
							{
								Key:   "CR LF",
								Value: []byte("\r\n"),
								Children: abnf.Nodes{
									{Key: "CR", Value: []byte("\r")},
									{Key: "LF", Value: []byte("\n")},
								},
							},
						},
					},
				},
			),
			Entry("\\n", []byte("\n"),
				abnf.Nodes{
					{
						Key:   "CRLF",
						Value: []byte("\n"),
						Children: abnf.Nodes{
							{Key: "LF", Value: []byte("\n")},
						},
					},
				},
			),
		)
	})

	Describe("CTL", func() {
		DescribeTable("", assertFn(abnf_core.CTL),
			Entry("\\u001B", []byte("\u001B"),
				abnf.Nodes{
					{
						Key:   "CTL",
						Value: []byte("\u001B"),
						Children: abnf.Nodes{
							{Key: "%x00-1F", Value: []byte("\u001B")},
						},
					},
				},
			),
		)
	})

	Describe("DIGIT", func() {
		DescribeTable("", assertFn(abnf_core.DIGIT),
			Entry("0", []byte("0"),
				abnf.Nodes{
					{Key: "DIGIT", Value: []byte("0")},
				},
			),
			Entry("9", []byte("9"),
				abnf.Nodes{
					{Key: "DIGIT", Value: []byte("9")},
				},
			),
		)
	})

	Describe("DQUOTE", func() {
		DescribeTable("", assertFn(abnf_core.DQUOTE),
			Entry("\"", []byte("\""),
				abnf.Nodes{
					{Key: "DQUOTE", Value: []byte("\"")},
				},
			),
		)
	})

	Describe("HEXDIG", func() {
		DescribeTable("", assertFn(abnf_core.HEXDIG),
			Entry("7", []byte("7"),
				abnf.Nodes{
					{
						Key:   "HEXDIG",
						Value: []byte("7"),
						Children: abnf.Nodes{
							{Key: "DIGIT", Value: []byte("7")},
						},
					},
				},
			),
			Entry("A", []byte("A"),
				abnf.Nodes{
					{
						Key:   "HEXDIG",
						Value: []byte("A"),
						Children: abnf.Nodes{
							{Key: "\"A\"", Value: []byte("A")},
						},
					},
					{
						Key:   "HEXDIG",
						Value: []byte("A"),
						Children: abnf.Nodes{
							{Key: "\"a\"", Value: []byte("A")},
						},
					},
				},
			),
			Entry("a", []byte("a"),
				abnf.Nodes{
					{
						Key:   "HEXDIG",
						Value: []byte("a"),
						Children: abnf.Nodes{
							{Key: "\"A\"", Value: []byte("a")},
						},
					},
					{
						Key:   "HEXDIG",
						Value: []byte("a"),
						Children: abnf.Nodes{
							{Key: "\"a\"", Value: []byte("a")},
						},
					},
				},
			),
		)
	})

	Describe("HTAB", func() {
		DescribeTable("", assertFn(abnf_core.HTAB),
			Entry("\\t", []byte("\t"),
				abnf.Nodes{
					{Key: "HTAB", Value: []byte("\t")},
				},
			),
		)
	})

	Describe("LWSP", func() {
		DescribeTable("", assertFn(abnf_core.LWSP),
			Entry("' '", []byte(" "),
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
			),
			Entry("'\\n '", []byte("\n "),
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
												Value: []byte(" "),
												Children: abnf.Nodes{
													{Key: "SP", Value: []byte(" ")},
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
			),
		)
	})

	Describe("OCTET", func() {
		DescribeTable("", assertFn(abnf_core.OCTET),
			Entry("o", []byte("o"),
				abnf.Nodes{
					{Key: "OCTET", Value: []byte("o")},
				},
			),
		)
	})

	Describe("VCHAR", func() {
		DescribeTable("", assertFn(abnf_core.VCHAR),
			Entry("`", []byte("`"),
				abnf.Nodes{
					{Key: "VCHAR", Value: []byte("`")},
				},
			),
		)
	})

	Describe("WSP", func() {
		DescribeTable("", assertFn(abnf_core.WSP),
			Entry("' '", []byte(" "),
				abnf.Nodes{
					{
						Key:   "WSP",
						Value: []byte(" "),
						Children: abnf.Nodes{
							{Key: "SP", Value: []byte(" ")},
						},
					},
				},
			),
			Entry("\\t", []byte("\t"),
				abnf.Nodes{
					{
						Key:   "WSP",
						Value: []byte("\t"),
						Children: abnf.Nodes{
							{Key: "HTAB", Value: []byte("\t")},
						},
					},
				},
			),
		)
	})
})

func BenchmarkComplex(b *testing.B) {
}
