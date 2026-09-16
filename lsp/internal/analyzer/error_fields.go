package analyzer

import "mutant/object"

// errorFieldTypes is the editor's view of the error field table the runtime
// implements in object.Error.Field. It exists so hovering `err.line` says `int`
// rather than `any`, and so completing `err.` offers the ten names instead of
// nothing.
//
// It is a second copy of a list that lives in the runtime, which is a drift risk
// -- so TestErrorFieldTableMatchesTheRuntime pins it against
// object.ErrorFieldNames(). A field added to the runtime and not to this table
// fails that test rather than quietly hovering as `any`. The types cannot come
// from the runtime the way the names do: object.Error.Field returns values, and
// this table is about what a *zero* error would answer with.
var errorFieldTypes = map[string]Type{
	"message":     {Kind: TypeString},
	"context":     {Kind: TypeString},
	"related":     {Kind: TypeHash},
	"file":        {Kind: TypeString},
	"line":        {Kind: TypeInt},
	"column":      {Kind: TypeInt},
	"end_line":    {Kind: TypeInt},
	"end_column":  {Kind: TypeInt},
	"source_line": {Kind: TypeString},
	"stack":       {Kind: TypeArray, Elem: &Type{Kind: TypeString}},
}

// errorFieldType reports the type of one field of an error.
func errorFieldType(name string) (Type, bool) {
	ty, ok := errorFieldTypes[name]
	return ty, ok
}

// errorFieldNames returns the field names in the runtime's declaration order,
// which is the order they are offered in for completion. Alphabetical would put
// `column` above `message`, and the first thing anyone wants off an error is its
// message.
func errorFieldNames() []string { return object.ErrorFieldNames() }
