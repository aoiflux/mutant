package builtin

import (
	"fmt"
	"mutant/object"
	"strings"
)

func Putf(args ...object.Object) object.Object {
	if len(args) == 0 {
		return nil
	}

	format := args[0].Inspect()
	if strings.Contains(format, "%") {
		vals := make([]any, 0, len(args)-1)
		for _, arg := range args[1:] {
			switch v := arg.(type) {
			case *object.Integer:
				vals = append(vals, v.Value)
			case *object.String:
				vals = append(vals, v.Value)
			case *object.Boolean:
				vals = append(vals, v.Value)
			case *object.Float:
				vals = append(vals, v.Value)
			default:
				vals = append(vals, v.Inspect())
			}

		}
		fmt.Printf(format, vals...)
		return nil
	}

	for _, arg := range args {
		fmt.Printf("%v", arg.Inspect())
	}
	return nil
}
