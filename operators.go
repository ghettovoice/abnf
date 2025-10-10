package abnf

import (
	"bytes"
	"sort"
	"unicode/utf8"

	"braces.dev/errtrace"
)

// Operator represents an ABNF operator.
type Operator = func(in []byte, pos uint, ns Nodes) (Nodes, error)

func literal(key string, want []byte, ci bool) Operator {
	return func(in []byte, pos uint, ns Nodes) (Nodes, error) {
		if len(in[pos:]) < len(want) {
			return ns, errtrace.Wrap(newOpError(key, pos, ErrNotMatched))
		}

		got := in[pos : int(pos)+len(want)]
		if !bytes.Equal(got, want) {
			if !ci || !bytes.Equal(toLower(want), toLower(got)) {
				return ns, errtrace.Wrap(newOpError(key, pos, ErrNotMatched))
			}
		}
		return append(ns, &Node{
			Key:   key,
			Pos:   pos,
			Value: got,
		}), nil
	}
}

// Literal defines a case-insensitive characters sequence.
// It returns ErrNotMatched if input doesn't match.
func Literal(key string, val []byte) Operator {
	return literal(key, val, true)
}

// LiteralCS defines a case-sensitive characters sequence.
// It returns ErrNotMatched if input doesn't match.
func LiteralCS(key string, val []byte) Operator {
	return literal(key, val, false)
}

// Range defines a range of alternative numeric values.
// It returns ErrNotMatched if input doesn't match.
func Range(key string, low, high []byte) Operator {
	return func(in []byte, pos uint, ns Nodes) (Nodes, error) {
		if len(in[pos:]) < len(low) || bytes.Compare(in[pos:int(pos)+len(low)], low) < 0 {
			return ns, errtrace.Wrap(newOpError(key, pos, ErrNotMatched))
		}

		var l int
		_, size := utf8.DecodeRune(in)
		for i := len(high); 0 < i; i-- {
			if len(high)-i < size && in[int(pos)+len(high)-i] <= high[i-1] {
				l++
			} else {
				break
			}
		}
		if l == 0 {
			return ns, errtrace.Wrap(newOpError(key, pos, ErrNotMatched))
		}
		return append(ns, &Node{
			Key:   key,
			Pos:   pos,
			Value: in[pos : int(pos)+l],
		}), nil
	}
}

func alt(key string, fm bool, op Operator, ops ...Operator) Operator {
	return func(in []byte, pos uint, ns Nodes) (Nodes, error) {
		var errs []error
		curns := newNodes()
		subns := newNodes()
		for _, op := range append([]Operator{op}, ops...) {
			var err error
			subns.clear()
			if subns, err = op(in, pos, subns); err == nil {
				for _, sn := range subns {
					curns = append(curns, &Node{
						Key:      key,
						Pos:      pos,
						Value:    in[pos : int(pos)+len(sn.Value)],
						Children: append(newNodes(), sn),
					})
				}
			} else {
				errs = append(errs, err)
			}

			if len(subns) > 0 && fm {
				break
			}
		}
		subns.free()

		if len(curns) > 0 {
			if len(curns) > 1 {
				sort.Sort(nodeSorter(curns))
			}
			ns = append(ns, curns...)
			errs = errs[:0]
		}
		curns.free()

		if len(errs) > 0 {
			return ns, errtrace.Wrap(newOpError(key, pos, joinErrs(errs...)))
		}
		return ns, nil
	}
}

// Alt defines a sequence of alternative elements that are separated by a forward slash ("/").
// Created operator will return all matched alternatives.
// It returns joined errors if all alternatives failed.
func Alt(key string, op Operator, ops ...Operator) Operator {
	return alt(key, false, op, ops...)
}

// AltFirst defines a sequence of alternative elements that are separated by a forward slash ("/").
// Created operator will return first matched alternative.
// It returns joined errors if all alternatives failed.
func AltFirst(key string, op Operator, ops ...Operator) Operator {
	return alt(key, true, op, ops...)
}

func concat(key string, all bool, op Operator, ops ...Operator) Operator {
	return func(in []byte, pos uint, ns Nodes) (Nodes, error) {
		var errs []error
		curns := newNodes()
		curns = append(curns, &Node{Key: key, Pos: pos, Value: in[pos:pos]})
		newns := newNodes()
		subns := newNodes()
		for _, op := range append([]Operator{op}, ops...) {
			newns.clear()
			for _, n := range curns {
				var err error
				subns.clear()
				if subns, err = op(in, n.Pos+uint(len(n.Value)), subns); err == nil {
					for _, sn := range subns {
						var nn *Node
						if len(subns) == 1 {
							nn = n
							nn.Value = in[n.Pos : int(n.Pos)+len(n.Value)+len(sn.Value)]
							nn.Children = append(n.Children, sn)
						} else {
							nn = &Node{
								Key:      n.Key,
								Pos:      n.Pos,
								Value:    in[n.Pos : int(n.Pos)+len(n.Value)+len(sn.Value)],
								Children: append(append(newNodes(), n.Children...), sn),
							}
						}
						newns = append(newns, nn)
					}
				} else {
					errs = append(errs, err)
				}
			}

			if len(newns) > 0 {
				curns.clear()
				curns = append(curns, newns...)
				errs = errs[:0]
			} else {
				curns.clear()
				break
			}
		}
		newns.free()
		subns.free()

		if len(curns) > 0 {
			if len(curns) > 1 && !all {
				curns[0] = curns.Best()
				curns1 := curns[1:]
				curns1.clear()
				curns = curns[:1]
			}
			ns = append(ns, curns...)
			errs = errs[:0]
		}
		curns.free()

		if len(errs) > 0 {
			return ns, errtrace.Wrap(newOpError(key, pos, joinErrs(errs...)))
		}
		return ns, nil
	}
}

// Concat defines a simple, ordered string of values.
// Created operator will return the longest alternative.
// It returns error if one of the operators failed.
func Concat(key string, op Operator, ops ...Operator) Operator {
	return concat(key, false, op, ops...)
}

// ConcatAll defines a simple, ordered string of values.
// Created operator will return all alternatives.
// It returns error if one of the operators failed.
func ConcatAll(key string, op Operator, ops ...Operator) Operator {
	return concat(key, true, op, ops...)
}

// Repeat defines a variable repetition.
// It returns error in case when operator wasn't matched min times.
func Repeat(key string, min, max uint, op Operator) Operator {
	var minOp Operator
	if min > 0 {
		ps := make([]Operator, min)
		for i := range min {
			ps[i] = op
		}
		minOp = concat(key, true, ps[0], ps[1:]...)
	}

	return func(in []byte, pos uint, ns Nodes) (Nodes, error) {
		resns := newNodes()
		if min == 0 {
			resns = append(resns, &Node{Key: key, Pos: pos, Value: in[pos:pos]})
		} else {
			var err error
			if resns, err = minOp(in, pos, resns); err != nil {
				return ns, errtrace.Wrap(err)
			}
		}

		var (
			errs []error
			i    uint
		)
		curns := append(newNodes(), resns...)
		newns := newNodes()
		subns := newNodes()
		if 0 < max && max < min {
			max = min
		}
		for i = min; i < max || max == 0; i++ {
			newns.clear()
			for _, n := range curns {
				var err error
				subns.clear()
				if subns, err = op(in, n.Pos+uint(len(n.Value)), subns); err == nil {
					for _, sn := range subns {
						var chns Nodes
						if len(subns) == 1 {
							chns = append(n.Children, sn)
						} else {
							chns = append(append(newNodes(), n.Children...), sn)
						}
						newns = append(newns, &Node{
							Key:      n.Key,
							Pos:      n.Pos,
							Value:    in[n.Pos : int(n.Pos)+len(n.Value)+len(sn.Value)],
							Children: chns,
						})
					}
				} else {
					errs = append(errs, err)
				}
			}
			if len(newns) > 0 && newns.Compare(curns) == 1 {
				curns.clear()
				curns = append(curns, newns...)
				resns = append(resns, newns...)
				errs = errs[:0]
			} else {
				break
			}
		}
		curns.free()
		newns.free()
		subns.free()

		if len(resns) > 0 {
			if len(resns) > 1 {
				sort.Sort(nodeSorter(resns))
			}
			ns = append(ns, resns...)
			errs = errs[:0]
		}
		resns.free()

		if len(errs) > 0 {
			return ns, errtrace.Wrap(newOpError(key, pos, joinErrs(errs...)))
		}
		return ns, nil
	}
}

// RepeatN defines a specific repetition.
// It returns error in case when operator wasn't matched n times.
func RepeatN(key string, n uint, op Operator) Operator {
	return Repeat(key, n, n, op)
}

// Repeat0Inf defines a specific repetition from 0 to infinity.
func Repeat0Inf(key string, op Operator) Operator {
	return Repeat(key, 0, 0, op)
}

// Repeat1Inf defines a specific repetition from 1 to infinity.
// It returns error in case when operator wasn't matched at least once.
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
