package object

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"math"
	"sort"
	"strings"
)

type HashKey struct {
	Type  ObjectType
	Value uint64
}

type HashPair struct {
	Key   Object
	Value Object
}

type Hash struct{ Pairs map[HashKey]HashPair }

type Hashable interface{ HashKey() HashKey }

func (b *Boolean) HashKey() HashKey {
	var value uint64
	if b.Value {
		value = 1
	} else {
		value = 0
	}
	return HashKey{Type: b.Type(), Value: value}
}

func (i *Integer) HashKey() HashKey {
	return HashKey{Type: i.Type(), Value: uint64(i.Value)}
}

func (f *Float) HashKey() HashKey {
	return HashKey{Type: f.Type(), Value: math.Float64bits(f.Value)}
}

func (s *String) HashKey() HashKey {
	h := fnv.New64a()
	h.Write([]byte(s.Value))
	return HashKey{Type: s.Type(), Value: h.Sum64()}
}

func (h *Hash) Type() ObjectType { return HASH_OBJ }
// Inspect renders the hash with its keys in a stable order.
//
// Pairs live in a Go map, and ranging a map yields a different order on every
// run. That made a program's own output differ run to run for the same input --
// which for reports that get diffed, hashed, or committed is a defect rather
// than a cosmetic detail. Sorting here rather than at each call site keeps every
// path that prints a hash (putln, putf, string conversion, nested hashes)
// consistent.
//
// Integer keys are ordered numerically, so {2: ..., 10: ...} does not come out
// with 10 first the way a plain string sort would.
func (h *Hash) Inspect() string {
	var out bytes.Buffer

	pairs := make([]HashPair, 0, len(h.Pairs))
	for _, pair := range h.Pairs {
		pairs = append(pairs, pair)
	}
	sort.Slice(pairs, func(i, j int) bool { return hashKeyLess(pairs[i].Key, pairs[j].Key) })

	rendered := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		rendered = append(rendered, fmt.Sprintf("%s: %s", pair.Key.Inspect(), pair.Value.Inspect()))
	}

	out.WriteString("{")
	out.WriteString(strings.Join(rendered, ", "))
	out.WriteString("}")

	return out.String()
}

// hashKeyLess orders keys of the same type naturally and groups differing types
// by type name, so a mixed-key hash still has one definite order.
func hashKeyLess(a, b Object) bool {
	if a.Type() != b.Type() {
		return a.Type() < b.Type()
	}

	switch left := a.(type) {
	case *Integer:
		if right, ok := b.(*Integer); ok {
			return left.Value < right.Value
		}
	case *String:
		if right, ok := b.(*String); ok {
			return left.Value < right.Value
		}
	case *Boolean:
		if right, ok := b.(*Boolean); ok {
			return !left.Value && right.Value
		}
	}

	return a.Inspect() < b.Inspect()
}
