package builtin

import (
	"bytes"
	"fmt"
	"mutant/object"
	"strings"
)

func Putln(args ...object.Object) object.Object {
	var b bytes.Buffer
	for i, arg := range args {
		part := arg.Inspect()
		if i == 0 {
			b.WriteString(part)
			continue
		}

		if shouldInsertSpaceBefore(part, b.String()) {
			b.WriteByte(' ')
		}
		b.WriteString(part)
	}

	fmt.Println(b.String())
	return nil
}

func shouldInsertSpaceBefore(next, current string) bool {
	if strings.TrimSpace(next) == "" || current == "" {
		return false
	}

	trimmedNext := strings.TrimLeft(next, " \t")
	if trimmedNext == "" {
		return false
	}

	if strings.HasPrefix(trimmedNext, ",") ||
		strings.HasPrefix(trimmedNext, ".") ||
		strings.HasPrefix(trimmedNext, ";") ||
		strings.HasPrefix(trimmedNext, ":") ||
		strings.HasPrefix(trimmedNext, ")") ||
		strings.HasPrefix(trimmedNext, "]") ||
		strings.HasPrefix(trimmedNext, "}") {
		return false
	}

	trimmedCurrent := strings.TrimRight(current, " \t")
	if trimmedCurrent == "" {
		return false
	}

	if strings.HasSuffix(trimmedCurrent, "=") ||
		strings.HasSuffix(trimmedCurrent, "(") ||
		strings.HasSuffix(trimmedCurrent, "[") ||
		strings.HasSuffix(trimmedCurrent, "{") {
		return false
	}

	return true
}
