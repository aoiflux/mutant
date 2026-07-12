package builtin

import (
	"fmt"
	"mutant/object"
	"strings"
)

func Putln(args ...object.Object) object.Object {
	parts := make([]string, 0, len(args))
	for _, arg := range args {
		parts = append(parts, arg.Inspect())
	}
	fmt.Println(strings.Join(parts, " "))
	return nil
}
