package abnf

import (
	"bytes"
	"sort"
	"unicode/utf8"
)

// Operator represents an ABNF operator.
type Operator = func(in []byte, pos uint, ns *Nodes) error

func literal(key string, want []byte, ci bool) Operator {
	return func(in []byte, pos uint, ns *Nodes) error {
		if len(in[pos:]) < len(want) {
			return operError{key, pos, ErrNotMatched} //errtrace:skip
		}

		got := in[pos : int(pos)+len(want)]
		if !bytes.Equal(got, want) {
			if !ci || !bytes.Equal(toLower(want), toLower(got)) {
				return operError{key, pos, ErrNotMatched} //errtrace:skip
			}
		}

		ns.Append(
			loadOrStoreNode(
				newNodeCacheKey(key, pos, uint(len(got)), in),
				func() *Node {
					return &Node{
						Key:   key,
						Pos:   pos,
						Value: got,
					}
				},
			),
		)
		return nil
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
	return func(in []byte, pos uint, ns *Nodes) error {
		if len(in[pos:]) < len(low) || bytes.Compare(in[pos:int(pos)+len(low)], low) < 0 {
			return operError{key, pos, ErrNotMatched} //errtrace:skip
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
			return operError{key, pos, ErrNotMatched} //errtrace:skip
		}

		ns.Append(
			loadOrStoreNode(
				newNodeCacheKey(key, pos, uint(l), in),
				func() *Node {
					return &Node{
						Key:   key,
						Pos:   pos,
						Value: in[pos : int(pos)+l],
					}
				},
			),
		)
		return nil
	}
}

func alt(key string, fm bool, op Operator, ops ...Operator) Operator {
	return func(in []byte, pos uint, ns *Nodes) error {
		resns := NewNodes()
		defer resns.Free()
		subns := NewNodes()
		defer subns.Free()

		errs := newMultiErr(uint(len(ops) + 1))

		runOp := func(op Operator) bool {
			subns.Clear()
			if err := op(in, pos, &subns); err == nil {
				for _, sn := range subns {
					resns.Append(
						loadOrStoreNode(
							newNodeCacheKey(key, pos, uint(len(sn.Value)), in, sn),
							func() *Node {
								nn := &Node{
									Key:   key,
									Pos:   pos,
									Value: in[pos : int(pos)+len(sn.Value)],
								}
								nn.Children = append(NewNodes(), sn)
								return nn
							},
						),
					)
				}
			} else {
				errs = append(errs, err)
			}

			if len(subns) > 0 && fm {
				return false
			}
			return true
		}

		if runOp(op) {
			for _, op := range ops {
				if !runOp(op) {
					break
				}
			}
		}

		if len(resns) > 0 {
			if len(resns) > 1 {
				sort.Sort(nodeSorter(resns))
			}
			ns.Append(resns...)
			errs.clear()
		}

		if len(errs) > 0 {
			return operError{key, pos, multiError(errs)} //errtrace:skip
		}
		errs.free()
		return nil
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
	return func(in []byte, pos uint, ns *Nodes) error {
		resns := NewNodes()
		defer resns.Free()

		resns.Append(
			loadOrStoreNode(
				newNodeCacheKey(key, pos, 0, in),
				func() *Node {
					return &Node{
						Key:   key,
						Pos:   pos,
						Value: in[pos:pos],
					}
				},
			),
		)

		newns := NewNodes()
		defer newns.Free()
		subns := NewNodes()
		defer subns.Free()

		errs := newMultiErr(uint(len(ops) + 1))

		runOp := func(op Operator) bool {
			newns.Clear()
			for _, n := range resns {
				subns.Clear()
				if err := op(in, n.Pos+uint(len(n.Value)), &subns); err == nil {
					for _, sn := range subns {
						ck := newNodeCacheKey(key, n.Pos, uint(len(n.Value)+len(sn.Value)), in, n.Children...)
						ck.writeChildKeys(0, sn)
						newns.Append(
							loadOrStoreNode(
								ck,
								func() *Node {
									nn := &Node{
										Key:   key,
										Pos:   n.Pos,
										Value: in[n.Pos : int(n.Pos)+len(n.Value)+len(sn.Value)],
									}
									nn.Children = append(append(NewNodes(), n.Children...), sn)
									return nn
								},
							),
						)
					}
				} else {
					errs = append(errs, err)
				}
			}

			if len(newns) > 0 {
				resns.Clear()
				resns.Append(newns...)
				errs.clear()
			} else {
				resns.Clear()
				return false
			}
			return true
		}

		if runOp(op) {
			for _, op := range ops {
				if !runOp(op) {
					break
				}
			}
		}

		if len(resns) > 0 {
			if len(resns) > 1 && !all {
				ns.Append(resns.Best())
			} else {
				ns.Append(resns...)
			}
			errs.clear()
		}

		if len(errs) > 0 {
			return operError{key, pos, multiError(errs)} //errtrace:skip
		}
		errs.free()
		return nil
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

	return func(in []byte, pos uint, ns *Nodes) error {
		resns := NewNodes()
		defer resns.Free()

		if min == 0 {
			resns.Append(
				loadOrStoreNode(
					newNodeCacheKey(key, pos, 0, in),
					func() *Node {
						return &Node{
							Key:   key,
							Pos:   pos,
							Value: in[pos:pos],
						}
					},
				),
			)
		} else {
			if err := minOp(in, pos, &resns); err != nil {
				return operError{key, pos, err} //errtrace:skip
			}
		}

		curns := NewNodes()
		defer curns.Free()
		curns.Append(resns...)

		newns := NewNodes()
		defer newns.Free()
		subns := NewNodes()
		defer subns.Free()

		if 0 < max && max < min {
			max = min
		}

		errs := newMultiErr(max - min + 1)

		for i := min; i < max || max == 0; i++ {
			newns.Clear()

			for _, n := range curns {
				subns.Clear()
				if err := op(in, n.Pos+uint(len(n.Value)), &subns); err == nil {
					for _, sn := range subns {
						ck := newNodeCacheKey(key, n.Pos, uint(len(n.Value)+len(sn.Value)), in, n.Children...)
						ck.writeChildKeys(0, sn)
						newns.Append(
							loadOrStoreNode(
								ck,
								func() *Node {
									nn := &Node{
										Key:   key,
										Pos:   n.Pos,
										Value: in[n.Pos : int(n.Pos)+len(n.Value)+len(sn.Value)],
									}
									nn.Children = append(append(NewNodes(), n.Children...), sn)
									return nn
								},
							),
						)
					}
				} else {
					errs = append(errs, err)
				}
			}

			if len(newns) > 0 && newns.Compare(curns) == 1 {
				curns.Clear()
				curns.Append(newns...)
				resns.Append(newns...)

				errs.clear()
			} else {
				break
			}
		}

		if len(resns) > 0 {
			if len(resns) > 1 {
				sort.Sort(nodeSorter(resns))
			}
			ns.Append(resns...)
			errs.clear()
		}

		if len(errs) > 0 {
			return operError{key, pos, multiError(errs)} //errtrace:skip
		}
		errs.free()
		return nil
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
