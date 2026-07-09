package object

import "strings"

type MultiValue struct{ Values []Object }

func (mv *MultiValue) Type() ObjectType { return MULTI_VALUE_OBJ }
func (mv *MultiValue) IsVoid() bool {
	if mv == nil || len(mv.Values) == 0 {
		return true
	}

	for _, value := range mv.Values {
		if value == nil {
			continue
		}
		if value.Type() != NULL_OBJ {
			return false
		}
	}

	return true
}
func (mv *MultiValue) Inspect() string {
	parts := make([]string, 0, len(mv.Values))
	for _, value := range mv.Values {
		if value == nil {
			parts = append(parts, "null")
			continue
		}
		parts = append(parts, value.Inspect())
	}
	return "(" + strings.Join(parts, ", ") + ")"
}
