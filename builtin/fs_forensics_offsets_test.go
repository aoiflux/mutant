package builtin

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"mutant/object"
)

// TestACarvedArtifactIsReportedWhereItStarts is M26-FS2-010's regression test.
// fs_carve's summary promises the offsets where each artifact starts, and the
// signature table records that an ISO-BMFF box carries 'ftyp' four bytes in and
// a tar header carries 'ustar' 257 bytes in -- but the offset reported was the
// magic's, 104 for a box at 100 and 769 for a tar at 512.
func TestACarvedArtifactIsReportedWhereItStarts(t *testing.T) {
	data := make([]byte, 2048)
	copy(data[100:], []byte{0, 0, 0, 0x18, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm'})
	copy(data[512+257:], "ustar")
	copy(data[1:], "ftyp") // magic three bytes in: no box can start four bytes earlier
	path := filepath.Join(t.TempDir(), "blob.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	for kind, want := range map[string][]int64{"mp4": {100}, "tar": {512}} {
		payload, errObj := unwrapPair(t, FsCarve(stringObj(path), stringObj(kind)))
		if errObj != nil {
			t.Fatalf("fs_carve(%s): %s", kind, errObj.Inspect())
		}
		var got []int64
		for _, hit := range payload.(*object.Array).Elements {
			got = append(got, mustHashIntValue(t, hit.(*object.Hash), "offset"))
		}
		if len(got) != len(want) || got[0] != want[0] {
			t.Errorf("fs_carve(%s) offsets = %v, want %v", kind, got, want)
		}
	}
}

// TestAWalksDepthDoesNotDependOnHowTheRootIsSpelled is M26-FS2-011's
// regression test. Depth counted separators in each path's spelling, so "."
// and its children "a" both had none: the walk from "." gave depth 0 to the
// root's children and, at max depth 1, returned a grandchild the walk from
// the absolute path left out.
func TestAWalksDepthDoesNotDependOnHowTheRootIsSpelled(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "a", "b"), 0o700); err != nil {
		t.Fatal(err)
	}

	walk := func(from string) []string {
		payload, errObj := unwrapPair(t, FsWalk(stringObj(from), intObj(1)))
		if errObj != nil {
			t.Fatalf("fs_walk(%q, 1): %s", from, errObj.Inspect())
		}
		var out []string
		for _, e := range payload.(*object.Array).Elements {
			entry := e.(*object.Hash)
			rel, err := filepath.Rel(from, mustHashStringValue(t, entry, "path"))
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, filepath.ToSlash(rel)+"@"+string(rune('0'+mustHashIntValue(t, entry, "depth"))))
		}
		sort.Strings(out)
		return out
	}

	absolute := walk(root)
	t.Chdir(root)
	relative := walk(".")
	want := []string{".@0", "a@1"}
	for name, got := range map[string][]string{"absolute": absolute, `"."`: relative} {
		if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
			t.Errorf("fs_walk from the %s root at max depth 1 = %v, want %v", name, got, want)
		}
	}
}
