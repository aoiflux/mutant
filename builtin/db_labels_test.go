package builtin

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"mutant/graphstore"
	"mutant/object"

	"github.com/aoiflux/graphene/store"
)

// writeLabelTable makes a directory whose graphene.labels says what body says.
func writeLabelTable(t *testing.T, body string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "store")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, graphstore.LabelTableName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// openDiskRefusal opens dir with db_open_disk and returns the refusal, closing
// the store if it was opened after all.
func openDiskRefusal(t *testing.T, dir string) string {
	t.Helper()
	value, errObj := unwrapPairNoFatal(DbOpenDisk(stringObj(dir)))
	if errObj == nil {
		DbClose(value)
		return ""
	}
	return errObj.Message
}

// M26-TOOL-004 and ARCH.03, one cause. graphene registers an opened store's
// label names for the whole process, and db_open_disk opened any directory
// without reading its table first. A store naming a label the disclose_*
// family declares, under another name, made every later disclosure write in
// the run fail; a store naming the custom labels db_* writes unnamed -- an
// exported symbol graph names custom 0 Module -- took db_* nodes that its own
// reader then could not decode. Both are refused before anything is opened.
func TestDbOpenDiskRefusesALabelTableThatWouldChangeWhatAWriteMeans(t *testing.T) {
	disclosureNodes, _ := disclosureTypeNames()
	numbers := make([]int, 0, len(disclosureNodes))
	for label := range disclosureNodes {
		numbers = append(numbers, int(label))
	}
	sort.Ints(numbers)
	first := store.NodeType(numbers[0])

	for _, c := range []struct {
		name, body string
		want       []string
	}{
		{"a disclosure label under another name",
			fmt.Sprintf("graphene-labels v1\nnode\t%d\tSuspect\n", first),
			[]string{"Suspect", disclosureNodes[first], "disclos"}},
		{"a name for a label db_* writes unnamed",
			fmt.Sprintf("graphene-labels v1\nnode\t%d\tModule\n", store.CustomNodeType(0)),
			[]string{"Module", "custom 0"}},
		{"an edge label db_* writes unnamed",
			fmt.Sprintf("graphene-labels v1\nedge\t%d\tIMPORTS\n", store.CustomEdgeType(3)),
			[]string{"IMPORTS", "custom 3"}},
		{"a torn table",
			fmt.Sprintf("graphene-labels v1\nnode\t%d\tSusp", store.CustomNodeType(3001)),
			[]string{"torn"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			refusal := openDiskRefusal(t, writeLabelTable(t, c.body))
			if refusal == "" {
				t.Fatal("db_open_disk opened it")
			}
			for _, want := range c.want {
				if !strings.Contains(refusal, want) {
					t.Errorf("the refusal does not name %q: %s", want, refusal)
				}
			}
		})
	}

	// What db_open_disk has always opened, it still opens: a new directory, a
	// store db_* wrote, and a table whose names this program does not use.
	for name, dir := range map[string]string{
		"a new store": filepath.Join(t.TempDir(), "new"),
		"a table naming labels no family uses": writeLabelTable(t,
			fmt.Sprintf("graphene-labels v1\nnode\t%d\tCarved\n", store.CustomNodeType(3000))),
	} {
		if refusal := openDiskRefusal(t, dir); refusal != "" {
			t.Errorf("%s was refused: %s", name, refusal)
		}
	}

	// And the disclosure family still writes afterwards in this process.
	f := newDiscloseFixture(t)
	mustHash(t, DiscloseToPassphrase(intObj(f.ledger), f.record, stringObj("counsel"), object.Object(stringObj("Counsel"))))
}
