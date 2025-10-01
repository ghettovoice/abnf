package abnf

import (
	"bytes"
	"sort"
	"unicode/utf8"
)

// Operator represents an ABNF operator.
type Operator func(s []byte, ns Nodes) Nodes

func literal(key string, val []byte, ci bool) Operator {
	return func(s []byte, ns Nodes) Nodes {
		if len(s) < len(val) {
			return ns
		}

		if !bytes.Equal(val, s[:len(val)]) {
			if !ci || !bytes.Equal(toLower(val), toLower(s[:len(val)])) {
				return ns
			}
		}

		return append(ns, &Node{
			Key:   key,
			Value: s[:len(val)],
		})
	}
}

// Literal defines a case-insensitive characters sequence.
func Literal(key string, val []byte) Operator {
	return literal(key, val, true)
}

// LiteralCS defines a case-sensitive characters sequence.
func LiteralCS(key string, val []byte) Operator {
	return literal(key, val, false)
}

// Range defines a range of alternative numeric values.
func Range(key string, low, high []byte) Operator {
	return func(s []byte, ns Nodes) Nodes {
		if len(s) < len(low) || bytes.Compare(s[:len(low)], low) < 0 {
			return ns
		}

		var l int
		_, size := utf8.DecodeRune(s)
		for i := len(high); 0 < i; i-- {
			if len(high)-i < size && s[len(high)-i] <= high[i-1] {
				l++
			} else {
				break
			}
		}
		if l == 0 {
			return ns
		}

		return append(ns, &Node{
			Key:   key,
			Value: s[:l],
		})
	}
}

func alt(key string, fm bool, oprts ...Operator) Operator {
	return func(s []byte, ns Nodes) Nodes {
		subns := newNodes()
		for _, op := range oprts {
			subns.clear()
			subns = op(s, subns)
			for _, sn := range subns {
				ns = append(ns, &Node{
					Key:      key,
					Value:    s[:len(sn.Value)],
					Children: append(newNodes(), sn),
				})
			}
			if len(subns) > 0 && fm {
				break
			}
		}
		subns.free()

		if len(ns) > 1 {
			sort.Sort(nodeSorter(ns))
		}
		return ns
	}
}

// Alt defines a sequence of alternative elements that are separated by a forward slash ("/").
// Created operator will return all matched alternatives.
func Alt(key string, oprts ...Operator) Operator {
	return alt(key, false, oprts...)
}

// AltFirst defines a sequence of alternative elements that are separated by a forward slash ("/").
// Created operator will return first matched alternative.
func AltFirst(key string, oprts ...Operator) Operator {
	return alt(key, true, oprts...)
}

func concat(key string, all bool, oprts ...Operator) Operator {
	return func(s []byte, ns Nodes) Nodes {
		if len(oprts) == 0 {
			return ns
		}

		ns = append(ns, &Node{Key: key, Value: s[:0]})
		newns := newNodes()
		subns := newNodes()
		for _, op := range oprts {
			newns.clear()
			for _, n := range ns {
				subns.clear()
				subns = op(s[len(n.Value):], subns)
				for _, sn := range subns {
					var nn *Node
					if len(subns) == 1 {
						nn = n
						nn.Value = s[:len(n.Value)+len(sn.Value)]
						nn.Children = append(n.Children, sn)
					} else {
						nn = &Node{
							Key:      n.Key,
							Value:    s[:len(n.Value)+len(sn.Value)],
							Children: append(append(newNodes(), n.Children...), sn),
						}
					}
					newns = append(newns, nn)
				}
			}
			if len(newns) > 0 {
				ns.clear()
				ns = append(ns, newns...)
			} else {
				ns.clear()
				break
			}
		}
		newns.free()
		subns.free()

		if len(ns) > 1 && !all {
			ns[0] = ns.Best()
			ns1 := ns[1:]
			ns1.clear()
			ns = ns[:1]
		}
		return ns
	}
}

// Concat defines a simple, ordered string of values.
// Created operator will return the longest alternative.
func Concat(key string, oprts ...Operator) Operator {
	return concat(key, false, oprts...)
}

// ConcatAll defines a simple, ordered string of values.
// Created operator will return all alternatives.
func ConcatAll(key string, oprts ...Operator) Operator {
	return concat(key, true, oprts...)
}

// Repeat defines a variable repetition.
func Repeat(key string, min, max uint, op Operator) Operator {
	var minp Operator
	if min > 0 {
		ps := make([]Operator, min)
		for i := uint(0); i < min; i++ {
			ps[i] = op
		}
		minp = concat(key, true, ps...)
	}

	return func(s []byte, ns Nodes) Nodes {
		if 0 < max && max < min {
			return ns
		}

		if min == 0 {
			ns = append(ns, &Node{Key: key, Value: s[:0]})
		} else {
			ns = minp(s, ns)
			if len(ns) == 0 {
				return ns
			}
		}
		if len(s) == 0 {
			return ns
		}

		curns := append(newNodes(), ns...)
		newns := newNodes()
		subns := newNodes()
		var i uint
		for i = min; i < max || max == 0; i++ {
			newns.clear()
			for _, n := range curns {
				subns.clear()
				subns = op(s[len(n.Value):], subns)
				for _, sn := range subns {
					var chns Nodes
					if len(subns) == 1 {
						chns = append(n.Children, sn)
					} else {
						chns = append(append(newNodes(), n.Children...), sn)
					}
					newns = append(newns, &Node{
						Key:      n.Key,
						Value:    s[:len(n.Value)+len(sn.Value)],
						Children: chns,
					})
				}
			}
			if len(newns) > 0 && newns.Compare(curns) == 1 {
				curns.clear()
				curns = append(curns, newns...)
				ns = append(ns, newns...)
			} else {
				break
			}
		}
		curns.free()
		newns.free()
		subns.free()

		if len(ns) > 1 {
			sort.Sort(nodeSorter(ns))
		}
		return ns
	}
}

// RepeatN defines a specific repetition.
func RepeatN(key string, n uint, op Operator) Operator {
	return Repeat(key, n, n, op)
}

// Repeat0Inf defines a specific repetition from 0 to infinity.
func Repeat0Inf(key string, op Operator) Operator {
	return Repeat(key, 0, 0, op)
}

// Repeat1Inf defines a specific repetition from 1 to infinity.
func Repeat1Inf(key string, op Operator) Operator {
	return Repeat(key, 1, 0, op)
}

// Optional defines an optional element sequence.
// It is equivalent to repeat 0-1.
func Optional(key string, op Operator) Operator {
	return Repeat(key, 0, 1, op)
}

type nodeSorter Nodes

func (ns nodeSorter) Len() int { return len(ns) }

func (ns nodeSorter) Less(i, j int) bool {
	return len(ns[i].Value) > len(ns[j].Value) ||
		len(ns[i].Children) > len(ns[j].Children)
}

func (ns nodeSorter) Swap(i, j int) { ns[i], ns[j] = ns[j], ns[i] }
