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
			return wrapNotMatched(key, pos)
		}

		got := in[pos : int(pos)+len(want)]
		if !bytes.Equal(got, want) {
			if !ci || !bytes.Equal(toLower(want), toLower(got)) {
				return wrapNotMatched(key, pos)
			}
		}

		ns.Append(loadOrStoreNode(
			newNodeCacheKey(key, pos, uint(len(got)), in),
			func() *Node { return &Node{Key: key, Pos: pos, Value: got} },
		))
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
			return wrapNotMatched(key, pos)
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
			return wrapNotMatched(key, pos) //errtrace:skip
		}

		ns.Append(loadOrStoreNode(
			newNodeCacheKey(key, pos, uint(l), in),
			func() *Node { return &Node{Key: key, Pos: pos, Value: in[pos : int(pos)+l]} },
		))
		return nil
	}
}

func alt(key string, fm bool, op Operator, ops ...Operator) Operator {
	return func(in []byte, pos uint, ns *Nodes) (finErr error) {
		resns, subns := NewNodes(), NewNodes()
		defer resns.Free()
		defer subns.Free()

		var me *multiError
		defer func() {
			if finErr == nil {
				me.free()
			}
		}()

		var (
			i int
			o Operator
		)
		for {
			if i == 0 {
				o = op
			} else {
				o = ops[i-1]
			}

			subns.Clear()
			if err := o(in, pos, subns); err != nil {
				if me == nil {
					me = newMultiErr(uint(len(ops) + 1))
				}
				*me = append(*me, err)

				if i == len(ops) {
					break
				}
				i++
				continue
			}

			for _, sn := range subns.All() {
				resns.Append(newAltNode(key, pos, sn, in))
			}

			if fm && subns.Len() > 0 {
				break
			}

			if i == len(ops) {
				break
			}
			i++
		}

		if resns.Len() > 0 {
			if resns.Len() > 1 {
				sort.Sort((*nodesSorter)(resns))
			}
			ns.Append(resns.All()...)
			me.clear()
		}

		if me != nil && len(*me) > 0 {
			return wrapOperError(key, pos, me) //errtrace:skip
		}
		return nil
	}
}

// newAltNode creates a new alternative node with the given key, position, and subnode
func newAltNode(key string, pos uint, sn *Node, in []byte) *Node {
	return loadOrStoreNode(
		newNodeCacheKey(key, pos, uint(len(sn.Value)), in, sn),
		func() *Node {
			chns := make(Nodes, 1)
			chns[0] = sn
			return &Node{
				Key:      key,
				Pos:      pos,
				Value:    in[pos : pos+uint(len(sn.Value))],
				Children: chns,
			}
		},
	)
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
	return func(in []byte, pos uint, ns *Nodes) (finErr error) {
		resns := NewNodes()
		defer resns.Free()
		resns.Append(loadOrStoreNode(
			newNodeCacheKey(key, pos, 0, in),
			func() *Node { return &Node{Key: key, Pos: pos, Value: in[pos:pos]} },
		))

		newns, subns := NewNodes(), NewNodes()
		defer newns.Free()
		defer subns.Free()

		var me *multiError
		defer func() {
			if finErr == nil {
				me.free()
			}
		}()

		var (
			i int
			o Operator
		)
		for {
			if i == 0 {
				o = op
			} else {
				o = ops[i-1]
			}

			newns.Clear()
			for _, n := range resns.All() {
				subns.Clear()
				if err := o(in, n.Pos+uint(len(n.Value)), subns); err != nil {
					if me == nil {
						me = newMultiErr(uint(len(ops) + 1))
					}
					*me = append(*me, err)
					continue
				}

				for _, sn := range subns.All() {
					newns.Append(newConcatNode(key, n, sn, in))
				}
			}

			if newns.Len() == 0 {
				resns.Clear()
				break
			}

			resns, newns = newns, resns
			me.clear()

			if i == len(ops) {
				break
			}
			i++
		}

		if resns.Len() > 0 {
			if resns.Len() > 1 && !all {
				ns.Append(resns.Best())
			} else {
				ns.Append(resns.All()...)
			}
			me.clear()
		}

		if me != nil && len(*me) > 0 {
			return wrapOperError(key, pos, me) //errtrace:skip
		}
		return nil
	}
}

// newConcatNode creates a new node that represents the concatenation of n and sn
func newConcatNode(key string, n, sn *Node, in []byte) *Node {
	ck := newNodeCacheKey(key, n.Pos, uint(len(n.Value)+len(sn.Value)), in, n.Children...)
	ck.writeChildKeys(0, sn)
	return loadOrStoreNode(ck, func() *Node {
		chns := make(Nodes, len(n.Children)+1)
		copy(chns, n.Children)
		chns[len(n.Children)] = sn
		return &Node{
			Key:      key,
			Pos:      n.Pos,
			Value:    in[n.Pos : int(n.Pos)+len(n.Value)+len(sn.Value)],
			Children: chns,
		}
	})
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
	// Create operator for minimum required repetitions
	var minOp Operator
	if min > 0 {
		ops := make([]Operator, min)
		for i := range min {
			ops[i] = op
		}
		minOp = concat(key, true, ops[0], ops[1:]...)
	}

	return func(in []byte, pos uint, ns *Nodes) error {
		resns := NewNodes()
		defer resns.Free()

		if min == 0 {
			resns.Append(loadOrStoreNode(
				newNodeCacheKey(key, pos, 0, in),
				func() *Node { return &Node{Key: key, Pos: pos, Value: in[pos:pos]} },
			))
		} else if err := minOp(in, pos, resns); err != nil {
			return wrapOperError(key, pos, err) //errtrace:skip
		}

		if 0 < max && max < min {
			max = min
		}

		if max != 0 && min == max {
			ns.Append(resns.All()...)
			return nil
		}

		curns, newns, subns := NewNodes(), NewNodes(), NewNodes()
		defer curns.Free()
		defer newns.Free()
		defer subns.Free()

		curns.Append(resns.All()...)

		for i := min; i < max || max == 0; i++ {
			newns.Clear()
			for _, n := range curns.All() {
				subns.Clear()
				if err := op(in, n.Pos+uint(len(n.Value)), subns); err != nil {
					// ignore errors, we already match min times
					continue
				}

				for _, sn := range subns.All() {
					newns.Append(newConcatNode(key, n, sn, in))
				}
			}

			if newns.Len() == 0 || newns.Compare(curns) != 1 {
				break
			}

			curns, newns = newns, curns
			resns.Append(curns.All()...)
		}

		if resns.Len() > 1 {
			sort.Sort((*nodesSorter)(resns))
		}
		ns.Append(resns.All()...)
		return nil
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
// It returns error in case when operator wasn't matched at least once.
func Repeat1Inf(key string, op Operator) Operator {
	return Repeat(key, 1, 0, op)
}

// Optional defines an optional element sequence.
// It is equivalent to repeat 0-1.
func Optional(key string, op Operator) Operator {
	return Repeat(key, 0, 1, op)
}
