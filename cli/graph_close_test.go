package cli

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoiflux/graphene"
)

// M26-TOOL-003. The export closed its store in a deferred call that threw the
// error away, so an export whose store could not be closed -- a WAL that would
// not close, a clean mark that would not persist -- reported success, and the
// next open found a store that had not been shut down cleanly. The close error
// is now the export's error.
func TestAnExportWhoseStoreFailsToCloseFails(t *testing.T) {
	previous := closeExportStore
	closeExportStore = func(g *graphene.Graph) error {
		// Closed for real, so the directory can be removed; the failure is
		// what the close reports.
		if err := previous(g); err != nil {
			return err
		}
		return errors.New("the clean-shutdown mark could not be written")
	}
	t.Cleanup(func() { closeExportStore = previous })

	root := writeTree(t, exportFixture)
	_, err := ExportGraph(ExportOptions{
		Entry: filepath.Join(root, "main.mut"),
		Out:   filepath.Join(t.TempDir(), "store"),
	})
	if err == nil {
		t.Fatal("an export whose store failed to close reported success")
	}
	if !strings.Contains(err.Error(), "clean-shutdown mark") {
		t.Fatalf("the export's error does not carry the close error: %v", err)
	}
}
