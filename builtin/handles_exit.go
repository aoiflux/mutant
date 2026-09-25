package builtin

import (
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/aoiflux/graphene"
)

// CloseForgottenHandles closes every ledger and disk graph store a program
// opened and never closed, and returns one sentence per store naming it.
//
// graphene marks a store cleanly shut down when it is closed. A store still
// open when the process exits is never marked, and the next open appends an
// unclean-restart entry to its audit log -- in a custody ledger, a permanent
// record of a crash that did not happen, which an examiner may later be asked
// to explain. The end of the program is the last moment anything can close
// it, so every path that runs a program to its end calls this: running a .mu,
// `mutant test`, the debugger and the REPL.
//
// An in-memory db_open graph has nothing on disk to leave unclean, and is
// closed without a word.
func CloseForgottenHandles() []string {
	var notes []string
	for _, handle := range sortedHandles(&ledgerHandles) {
		value, found := ledgerHandles.LoadAndDelete(handle)
		session, ok := value.(*ledgerSession)
		if !found || !ok {
			continue
		}
		notes = append(notes, forgottenNote("ledger", session.path, handle, BuiltinNameLedgerClose, session.graph.Close()))
	}
	for _, handle := range sortedHandles(&dbHandles) {
		value, found := dbHandles.LoadAndDelete(handle)
		g, ok := value.(*graphene.Graph)
		if !found || !ok {
			continue
		}
		dbTimelineForget(handle)
		path, onDisk := dbDiskPaths.LoadAndDelete(handle)
		err := g.Close()
		if onDisk {
			notes = append(notes, forgottenNote("graph store", path.(string), handle, BuiltinNameDbClose, err))
		}
	}
	return notes
}

// ReportForgottenHandles is CloseForgottenHandles for a program run from the
// command line: each note goes to w, which is stderr, so the program's own
// value on stdout is exactly what it was.
func ReportForgottenHandles(w io.Writer) {
	for _, note := range CloseForgottenHandles() {
		fmt.Fprintln(w, "[warning] "+note)
	}
}

// sortedHandles lists a handle table's keys in the order they were issued, so
// the notes read in the order the program opened the stores.
func sortedHandles(table *sync.Map) []int64 {
	var handles []int64
	table.Range(func(key, _ any) bool {
		if handle, ok := key.(int64); ok {
			handles = append(handles, handle)
		}
		return true
	})
	slices.Sort(handles)
	return handles
}

func forgottenNote(kind, path string, handle int64, closer string, err error) string {
	if err != nil {
		return fmt.Sprintf("%s %s (handle %d) was never closed with %s, and closing it at the end of the "+
			"program failed: %v. Its next open may be recorded as a restart after an unclean shutdown",
			kind, path, handle, closer, err)
	}
	return fmt.Sprintf("%s %s (handle %d) was never closed with %s; it was closed at the end of the program",
		kind, path, handle, closer)
}
