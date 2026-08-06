//go:build windows

package builtin

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"mutant/object"
)

// TestEvtxParseRealFile runs evtx_parse end-to-end against a real Windows Event
// Log from this machine, validating the full BinXML pipeline (not just the
// conversion layer). It picks the smallest readable .evtx and skips gracefully
// if none are accessible (e.g. ACLs on a locked-down host or CI).
func TestEvtxParseRealFile(t *testing.T) {
	logDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "winevt", "Logs")
	matches, _ := filepath.Glob(filepath.Join(logDir, "*.evtx"))
	if len(matches) == 0 {
		t.Skip("no .evtx files found")
	}
	// Smallest first — fastest to parse and most likely readable.
	sort.Slice(matches, func(i, j int) bool {
		fi, _ := os.Stat(matches[i])
		fj, _ := os.Stat(matches[j])
		if fi == nil || fj == nil {
			return false
		}
		return fi.Size() < fj.Size()
	})

	for _, path := range matches {
		payload, errObj := unwrapPair(t, EvtxParse(stringObj(path)))
		if errObj != nil {
			continue // unreadable/locked — try the next
		}
		h := payload.(*object.Hash)
		if hStr(t, h, "source") != "evtx" {
			t.Fatalf("source = %q", hStr(t, h, "source"))
		}
		recs := hashValueByKey(h, "records").(*object.Array)
		t.Logf("parsed %s: %d chunks, %d records",
			filepath.Base(path), hInt(t, h, "chunk_count"), int64(len(recs.Elements)))

		// Validate structural invariants on any records present.
		for i, e := range recs.Elements {
			if i >= 20 {
				break
			}
			rec := e.(*object.Hash)
			if hInt(t, rec, "record_id") <= 0 {
				t.Errorf("record %d: non-positive record_id", i)
			}
			if _, ok := hashValueByKey(rec, "event").(*object.Hash); !ok {
				t.Errorf("record %d: event is not a hash", i)
			}
		}
		return // one successfully-parsed log is enough
	}
	t.Skip("no readable .evtx files (all access-denied)")
}
