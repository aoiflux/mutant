// Package serialize holds the one list of object types that cross a gob
// boundary, so the encoder and the decoder cannot disagree about it.
//
// The list used to be written out three times -- in the generator, in the
// runner, and in a compiler test -- and it drifted: the generator was missing
// Struct, EnumValue and LuaPatch that the runner registered. Drift like that
// does not fail at build time. It fails when a program happens to carry one of
// the missing types across the boundary, which is the worst moment to find out.
package serialize

import (
	"encoding/gob"
	"sync"

	"mutant/builtin"
	"mutant/object"
)

// GobTypes is every type that may appear in an interface-typed field of a
// serialised ByteCode -- which in practice means every implementation of
// object.Object, plus the builtin wrapper.
//
// The rule is deliberately "all of them" rather than "the ones we currently
// emit". A type that is unreachable today becomes reachable the moment someone
// adds a constant folding pass or a new literal form, and the cost of carrying
// an unused registration is a single map entry.
func GobTypes() []any {
	return []any{
		&object.Array{},
		&object.Boolean{},
		&object.Break{},
		&object.Bytes{},
		// A cell is created at frame entry and dies with the frame, so nothing
		// this compiler emits can put one in a constant pool. It is registered
		// anyway, under the rule above: the cost is one map entry, and the
		// alternative is that the day something does reach gob the failure is a
		// runtime encoding error in the field rather than a caught mistake.
		&object.Cell{},
		&object.Closure{},
		&object.CompiledFunction{},
		&object.Continue{},
		&object.Encrypted{},
		&object.EnumValue{},
		&object.Error{},
		&object.Float{},
		&object.Function{},
		&object.Hash{},
		&object.Integer{},
		&object.LuaPatch{},
		&object.Macro{},
		&object.MultiValue{},
		&object.Null{},
		&object.Quote{},
		&object.ReturnValue{},
		&object.String{},
		&object.Struct{},
		&builtin.BuiltIn{},
	}
}

var registerOnce sync.Once

// RegisterGobTypes registers every type in GobTypes with encoding/gob. It is
// safe to call from anywhere, any number of times.
func RegisterGobTypes() {
	registerOnce.Do(func() {
		for _, t := range GobTypes() {
			gob.Register(t)
		}
	})
}
