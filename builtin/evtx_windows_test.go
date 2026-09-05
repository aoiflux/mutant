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
// if none are accessible (e.g. ACLs on a locked-down host or CI). The log path
// is the fixed Windows location (no environment variables, per project policy).
func TestEvtxParseRealFile(t *testing.T) {
	logDir := filepath.Join(`C:\Windows`, "System32", "winevt", "Logs")
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

// readableEvtx returns the smallest .evtx on this machine that actually parses,
// or "" when none do. The logs are ACL'd on a locked-down host, so every test
// here has to survive finding nothing. The path is the fixed Windows location
// (no environment variables, per project policy).
func readableEvtx(t *testing.T) string {
	t.Helper()

	matches, _ := filepath.Glob(filepath.Join(`C:\Windows`, "System32", "winevt", "Logs", "*.evtx"))
	sort.Slice(matches, func(i, j int) bool {
		fi, _ := os.Stat(matches[i])
		fj, _ := os.Stat(matches[j])
		if fi == nil || fj == nil {
			return false
		}
		return fi.Size() < fj.Size()
	})
	for _, path := range matches {
		if _, errObj := unwrapPairNoFatal(EvtxParse(stringObj(path))); errObj == nil {
			return path
		}
	}
	return ""
}

// countEvtxKinds walks a parsed event tree and tallies how many values came back
// as buffers and how many as strings.
func countEvtxKinds(o object.Object, nbytes, nstrings *int) {
	switch v := o.(type) {
	case *object.Bytes:
		*nbytes++
	case *object.String:
		*nstrings++
	case *object.Array:
		for _, e := range v.Elements {
			countEvtxKinds(e, nbytes, nstrings)
		}
	case *object.Hash:
		for _, pair := range v.Pairs {
			countEvtxKinds(pair.Value, nbytes, nstrings)
		}
	}
}

// TestEvtxParseBytesRealFile runs both builtins over the same real log and
// compares what came back. The synthetic tests pin the one arm that differs;
// this checks that a genuine BinXML pipeline reaches it, and that nothing else
// moved -- same record count, and not one buffer anywhere in evtx_parse's tree.
func TestEvtxParseBytesRealFile(t *testing.T) {
	path := readableEvtx(t)
	if path == "" {
		t.Skip("no readable .evtx files (all access-denied)")
	}

	plain, errObj := unwrapPair(t, EvtxParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("evtx_parse: %s", errObj.Inspect())
	}
	raw, errObj := unwrapPair(t, EvtxParseBytes(stringObj(path)))
	if errObj != nil {
		t.Fatalf("evtx_parse_bytes: %s", errObj.Inspect())
	}

	plainHash, rawHash := plain.(*object.Hash), raw.(*object.Hash)
	if a, b := hInt(t, plainHash, "count"), hInt(t, rawHash, "count"); a != b {
		t.Fatalf("record counts differ: evtx_parse %d, evtx_parse_bytes %d", a, b)
	}
	if hInt(t, plainHash, "count") == 0 {
		t.Skip("the readable log is empty; the comparison proves nothing")
	}

	var plainBytes, plainStrings, rawBytes, rawStrings int
	countEvtxKinds(hashValueByKey(plainHash, "records"), &plainBytes, &plainStrings)
	countEvtxKinds(hashValueByKey(rawHash, "records"), &rawBytes, &rawStrings)

	t.Logf("%s: evtx_parse BYTES=%d STRING=%d, evtx_parse_bytes BYTES=%d STRING=%d",
		filepath.Base(path), plainBytes, plainStrings, rawBytes, rawStrings)

	if plainBytes != 0 {
		t.Errorf("evtx_parse returned %d buffers; it is supposed to hex-encode", plainBytes)
	}
	// Binary is not in every log, so its absence is reported rather than failed.
	// What must hold either way is that the two disagree only by moving values
	// from the string column to the byte column, never by losing any.
	if rawBytes == 0 {
		t.Logf("no binary values in %s; only the no-binary path was exercised", filepath.Base(path))
	}
	if plainStrings != rawStrings+rawBytes {
		t.Errorf("value counts do not line up: evtx_parse had %d strings, evtx_parse_bytes has %d strings + %d buffers",
			plainStrings, rawStrings, rawBytes)
	}
}
