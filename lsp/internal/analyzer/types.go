package analyzer

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
)

// Type is a static type in the lattice. Name carries the struct/enum name;
// Elem carries an array's element type (optional).
type Type struct {
	Kind TypeKind
	Name string
	Elem *Type
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
	default:
		return "any"
	}
}

// arrayOf builds an array type with the given element type.
func arrayOf(elem Type) Type {
	e := elem
	return Type{Kind: TypeArray, Elem: &e}
}
