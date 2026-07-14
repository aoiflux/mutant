package builtin

import (
	"fmt"
	"mutant/object"
)

func Putf(args ...object.Object) object.Object {
	for _, arg := range args {
		fmt.Printf("%v", arg.Inspect())
	}
	return nil
}
