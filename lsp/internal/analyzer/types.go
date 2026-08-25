package analyzer

import "strings"

// This file defines the static type lattice used by the language server's
// best-effort type inference (see infer.go). It has ZERO runtime effect: the
// compiler, VM, and evaluator never see these types. `Any` is the gradual
// unknown — it is the safe default for anything not confidently inferred, so the
// worst case is simply that the editor shows no extra type information.

type TypeKind int

const (
	TypeAny TypeKind = iota
	TypeInt
	TypeFloat
	TypeBool
	TypeString
	TypeArray
	TypeHash
	TypeStruct
	TypeEnum
	TypeFunction
	TypeError
	TypeNull
	// TypeMulti is the MULTI_VALUE a (value, err) builtin returns when it is
	// bound to a single name. `let data = fs_read(p)` stores the whole pair —
	// evaluator.go takes the len(names) <= 1 branch and binds the value
	// unchanged — so typing data as `string` was a lie the editor told.
	TypeMulti
)

// Type is a static type in the lattice. Name carries the struct/enum name;
// Elem carries an array's element type (optional); Ret carries a function's
// inferred return type (optional, only for Kind == TypeFunction); Parts carries
// the components of a TypeMulti.
type Type struct {
	Kind  TypeKind
	Name  string
	Elem  *Type
	Ret   *Type
	Parts []Type
}

// multiOf builds the (value, error) pair a fallible builtin returns.
func multiOf(value Type) Type {
	return Type{Kind: TypeMulti, Parts: []Type{value, {Kind: TypeError}}}
}

// AnyType is the shared gradual-unknown value.
var AnyType = Type{Kind: TypeAny}

// IsKnown reports whether the type carries information worth showing (i.e. is not
// the gradual unknown).
func (t Type) IsKnown() bool { return t.Kind != TypeAny }

// String renders the type for display in hover, completion detail, and inlay
// hints (e.g. "int", "string", "[]int", "Point", "Color", "fn", "error").
func (t Type) String() string {
	switch t.Kind {
	case TypeInt:
		return "int"
	case TypeFloat:
		return "float"
	case TypeBool:
		return "bool"
	case TypeString:
		return "string"
	case TypeHash:
		return "hash"
	case TypeFunction:
		if t.Ret != nil && t.Ret.IsKnown() {
			return "fn -> " + t.Ret.String()
		}
		return "fn"
	case TypeError:
		return "error"
	case TypeNull:
		return "null"
	case TypeArray:
		if t.Elem != nil && t.Elem.IsKnown() {
			return "[]" + t.Elem.String()
		}
		return "array"
	case TypeStruct:
		if t.Name != "" {
			return t.Name
		}
		return "struct"
	case TypeEnum:
		if t.Name != "" {
			return t.Name
		}
		return "enum"
	case TypeMulti:
		parts := make([]string, 0, len(t.Parts))
		for _, part := range t.Parts {
			parts = append(parts, part.String())
		}
		return "(" + strings.Join(parts, ", ") + ")"
	default:
		return "any"
	}
}

// arrayOf builds an array type with the given element type.
func arrayOf(elem Type) Type {
	e := elem
	return Type{Kind: TypeArray, Elem: &e}
}
