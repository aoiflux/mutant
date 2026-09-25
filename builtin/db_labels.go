package builtin

import (
	"errors"
	"path/filepath"
	"slices"

	"mutant/graphstore"
	"mutant/object"

	"github.com/aoiflux/graphene/store"
)

// dbRefuseForeignLabels refuses a directory whose label table would change
// what a db_* write means, or would stop the disclose_* family for the rest of
// the process. It reads the table before anything is opened, because opening
// is what registers it.
//
// graphene registers an opened store's label names process-wide, one name per
// number, and whoever declares a different name for a number second gets an
// error. Two consequences follow, and both are refused here:
//
//   - db_* writes its nodes and edges under custom labels 0-127 and never
//     names them. A table that names one of those numbers belongs to a program
//     that reads it as something -- `mutant graph export` names custom node 0
//     Module -- and a node written here would read to that program as one.
//   - A table that gives a number the disclose_* family declares another name
//     registers first, and every later disclosure, withdrawal or
//     reclassification in the run fails.
//
// A directory with no table -- a new store, or one db_* wrote -- opens as it
// always has, and so does a table naming only labels this program never uses.
// A table that cannot be read is refused rather than half-registered: graphene
// reads a torn last line as a shorter name and registers that.
func dbRefuseForeignLabels(dir string) *object.Error {
	nodes, edges, err := graphstore.ReadLabelTable(filepath.Join(dir, graphstore.LabelTableName))
	switch {
	case errors.Is(err, graphstore.ErrNoLabelTable):
		return nil
	case err != nil:
		return newError("%s: %s cannot be opened, because %s", BuiltinNameDbOpenDisk, dir, err.Error())
	}
	disclosureNodes, disclosureEdges := disclosureTypeNames()
	for _, number := range sortedLabelNumbers(nodes) {
		label := store.NodeType(number)
		if errObj := dbForeignLabel(dir, "node", number, nodes[number],
			label >= store.NodeTypeCustomBase && label < store.NodeTypeCustomBase+ledgerScriptTypes,
			uint16(label-store.NodeTypeCustomBase), disclosureNodes[label]); errObj != nil {
			return errObj
		}
	}
	for _, number := range sortedLabelNumbers(edges) {
		label := store.EdgeType(number)
		if errObj := dbForeignLabel(dir, "edge", number, edges[number],
			label >= store.EdgeTypeCustomBase && label < store.EdgeTypeCustomBase+ledgerScriptTypes,
			uint16(label-store.EdgeTypeCustomBase), disclosureEdges[label]); errObj != nil {
			return errObj
		}
	}
	return nil
}

// dbForeignLabel is the refusal for one named label, or nil.
func dbForeignLabel(dir, kind string, number uint16, name string, scriptRange bool, custom uint16, disclosureName string) *object.Error {
	switch {
	case scriptRange:
		return newError("%s: %s names %s label %d (custom %d) %q, and db_* writes its own %ss under custom "+
			"labels 0-%d without naming them, so one written here would read as %q to the program that "+
			"named it. A symbol graph written by `mutant graph export` is read with `mutant graph query`",
			BuiltinNameDbOpenDisk, dir, kind, number, custom, name, kind, ledgerScriptTypes-1, name)
	case disclosureName != "" && disclosureName != name:
		return newError("%s: %s names %s label %d %q, which the disclosure ledger's schema names %q. graphene "+
			"keeps one name per label for the whole process, so opening it would stop every disclosure, "+
			"withdrawal and reclassification for the rest of this run", BuiltinNameDbOpenDisk, dir, kind,
			number, name, disclosureName)
	}
	return nil
}

// sortedLabelNumbers orders a label table's numbers, so a refusal names the
// same label every time it is produced.
func sortedLabelNumbers(table map[uint16]string) []uint16 {
	numbers := make([]uint16, 0, len(table))
	for number := range table {
		numbers = append(numbers, number)
	}
	slices.Sort(numbers)
	return numbers
}

// DisclosureLabelNames is the label table the disclose_* family declares in a
// ledger. It is exported for one reader: the test beside the symbol graph's
// own table, which proves no label number means two things in one process.
func DisclosureLabelNames() (map[store.NodeType]string, map[store.EdgeType]string) {
	return disclosureTypeNames()
}
