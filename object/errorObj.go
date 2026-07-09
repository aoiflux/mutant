package object

import (
	"fmt"
	"sort"
	"strings"
)

type Error struct {
	Message string
	Context string
	Related map[string]string
}

func (e *Error) Type() ObjectType { return ERROR_OBJ }
func (e *Error) Inspect() string {
	if e == nil {
		return "ERROR:<nil>"
	}

	parts := []string{"ERROR:" + e.Message}
	if e.Context != "" {
		parts = append(parts, "context="+e.Context)
	}
	if len(e.Related) > 0 {
		keys := make([]string, 0, len(e.Related))
		for key := range e.Related {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		relatedParts := make([]string, 0, len(keys))
		for _, key := range keys {
			relatedParts = append(relatedParts, fmt.Sprintf("%s=%s", key, e.Related[key]))
		}
		parts = append(parts, "related={"+strings.Join(relatedParts, ",")+"}")
	}

	return strings.Join(parts, " ")
}
