package main

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"mutant/builtin"
)

// graphDatabaseRow is one row of GRAPH_DATABASE.md's capability table:
// | `db_name` | `(arguments)` | returns |
var graphDatabaseRow = regexp.MustCompile("(?m)^\\| `(db_[a-z_]+)` \\| `(\\([^`]*\\))` \\|")

// TestGraphDatabaseTableMatchesTheSignatures: GRAPH_DATABASE.md's capability
// table is written by hand, and it fell behind the builtins it describes --
// db_open_disk was listed as `(path)` long after it took an options hash
// (M26-DOC2-009). Every db_* builtin is a row, and every row's arguments are the
// ones the builtin's own signature declares.
func TestGraphDatabaseTableMatchesTheSignatures(t *testing.T) {
	doc := readRepoFile(t, "../../docs/GRAPH_DATABASE.md")
	listed := map[string]string{}
	for _, m := range graphDatabaseRow.FindAllStringSubmatch(doc, -1) {
		listed[m[1]] = m[2]
	}
	if len(listed) == 0 {
		t.Fatal("docs/GRAPH_DATABASE.md has no capability table rows this test can read; update the pattern if the table moved")
	}

	for _, def := range builtin.Builtins {
		if !strings.HasPrefix(def.Name, "db_") {
			continue
		}
		signature, _, _, ok := builtin.TeachingDoc(def.Name)
		if !ok {
			t.Errorf("%s has no teaching doc to compare the table with", def.Name)
			continue
		}
		want := strings.TrimPrefix(signature, def.Name)
		got, found := listed[def.Name]
		switch {
		case !found:
			t.Errorf("docs/GRAPH_DATABASE.md's capability table has no row for %s%s", def.Name, want)
		case got != want:
			t.Errorf("docs/GRAPH_DATABASE.md lists %s as `%s`; its signature is `%s`", def.Name, got, want)
		}
		delete(listed, def.Name)
	}

	stale := make([]string, 0, len(listed))
	for name := range listed {
		stale = append(stale, name)
	}
	sort.Strings(stale)
	for _, name := range stale {
		t.Errorf("docs/GRAPH_DATABASE.md lists %s, which is not a builtin", name)
	}
}
