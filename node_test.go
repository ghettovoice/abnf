package abnf_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/ghettovoice/abnf"
)

func TestNode_GetNode(t *testing.T) {
	n := &abnf.Node{
		Key:   "ab",
		Value: []byte("abcc"),
		Children: abnf.Nodes{
			{Key: "a", Value: []byte("a")},
			{Key: "b", Value: []byte("b")},
			{Key: "c", Value: []byte("c")},
			{Key: "c", Value: []byte("c")},
		},
	}

	if got, ok := n.GetNode("ab"); !ok || !cmp.Equal(got, n, cmpopts.EquateEmpty()) {
		t.Errorf("n.GetNode(\"ab\") = (%+v, %v), want (%+v, true)\ndiff (-got +want):\n%v",
			got, ok, n,
			cmp.Diff(got, n, cmpopts.EquateEmpty()),
		)
	}
	if got, ok := n.GetNode("a"); !ok || !cmp.Equal(got, &abnf.Node{Key: "a", Value: []byte("a")}, cmpopts.EquateEmpty()) {
		t.Errorf("n.GetNode(\"a\") = (%+v, %v), want (%+v, true)\ndiff (-got +want):\n%v",
			got, ok,
			&abnf.Node{Key: "a", Value: []byte("a")},
			cmp.Diff(got, &abnf.Node{Key: "a", Value: []byte("a")}, cmpopts.EquateEmpty()),
		)
	}
	if got, ok := n.GetNode("d"); ok || got != nil {
		t.Errorf("n.GetNode(\"d\") = (%+v, %v), want (nil, false)", got, ok)
	}
}

func TestNodes_Best(t *testing.T) {
	ns := abnf.Nodes{
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
	want := &abnf.Node{
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
	}

	if got := ns.Best(); !cmp.Equal(got, want, cmpopts.EquateEmpty()) {
		t.Fatalf("ns.Best() = %+v, want %+v\ndiff (-got +want):\n%v",
			got, want,
			cmp.Diff(got, want, cmpopts.EquateEmpty()),
		)
	}
}
