package abnf_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/ghettovoice/abnf"
)

var _ = Describe("ABNF", func() {
	Describe("Node", func() {
		var n *abnf.Node

		BeforeEach(func() {
			n = &abnf.Node{
				Key:   "ab",
				Value: []byte("abcc"),
				Children: abnf.Nodes{
					{Key: "a", Value: []byte("a")},
					{Key: "b", Value: []byte("b")},
					{Key: "c", Value: []byte("c")},
					{Key: "c", Value: []byte("c")},
				},
			}
		})

		It("should search starting from self", func() {
			Expect(n.GetNode("ab")).Should(Equal(n))
			Expect(n.GetNode("a")).Should(Equal(&abnf.Node{Key: "a", Value: []byte("a")}))
			Expect(n.GetNode("d")).Should(BeZero())
		})
	})

	Describe("Nodes", func() {
		var ns abnf.Nodes

		BeforeEach(func() {
			ns = abnf.Nodes{
				{
					Key:   "abc",
					Value: []byte("abc"),
					Children: abnf.Nodes{
						{Key: "a", Value: []byte("a")},
						{Key: "b", Value: []byte("b")},
						{Key: "c", Value: []byte("c")},
					},
				},
				{
					Key:   "abcd",
					Value: []byte("abcd"),
					Children: abnf.Nodes{
						{Key: "a", Value: []byte("a")},
						{Key: "b", Value: []byte("b")},
						{
							Key:   "cd",
							Value: []byte("cd"),
							Children: abnf.Nodes{
								{Key: "c", Value: []byte("c")},
								{Key: "d", Value: []byte("d")},
							},
						},
					},
				},
			}
		})

		It("should search one", func() {
			Expect(ns.Get("d")).Should(Equal(&abnf.Node{Key: "d", Value: []byte("d")}))
			Expect(ns.Get("h")).Should(BeZero())
		})

		It("should search all", func() {
			Expect(ns.GetAll("c")).Should(Equal(abnf.Nodes{
				{Key: "c", Value: []byte("c")},
				{Key: "c", Value: []byte("c")},
			}))
		})

		It("should search best", func() {
			Expect(ns.Best()).Should(Equal(&abnf.Node{
				Key:   "abcd",
				Value: []byte("abcd"),
				Children: abnf.Nodes{
					{Key: "a", Value: []byte("a")},
					{Key: "b", Value: []byte("b")},
					{
						Key:   "cd",
						Value: []byte("cd"),
						Children: abnf.Nodes{
							{Key: "c", Value: []byte("c")},
							{Key: "d", Value: []byte("d")},
						},
					},
				},
			}))

			Expect(ns[:1].Best()).Should(Equal(&abnf.Node{
				Key:   "abc",
				Value: []byte("abc"),
				Children: abnf.Nodes{
					{Key: "a", Value: []byte("a")},
					{Key: "b", Value: []byte("b")},
					{Key: "c", Value: []byte("c")},
				},
			}))

			Expect(ns[:0].Best()).Should(BeZero())
		})

		It("should be comparable by best node", func() {
			ns1 := ns[:1]
			ns2 := ns[1:]

			Expect(ns1.Compare(ns2)).Should(Equal(-1))
			Expect(ns2.Compare(ns1)).Should(Equal(1))
		})
	})
})
