package builtin

import (
	"fmt"
	"mutant/object"
	"strings"
)

func Putf(args ...object.Object) object.Object {
	// `putf()` used to return nil and print nothing, which made it the one
	// builtin that answered a wrong argument count with silence. It also put
	// the implementation at odds with the `putf(format, ...values)` signature
	// the language server derives its argument-count diagnostic from. Reporting
	// the missing format the way every other builtin reports a missing argument
	// keeps the two in agreement.
	if len(args) == 0 {
		return newError("wrong number of arguments. got=0, want=at least 1")
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
