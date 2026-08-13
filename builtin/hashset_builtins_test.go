package builtin

import (
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

func TestHashsetLoadContainsClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known.txt")
	// Mixed content: a header, a comment, a plain hash, an NSRL-style CSV row,
	// an uppercase hash, and a blank line.
	content := "" +
		"SHA-1,MD5,FileName\n" +
		"# a comment\n" +
		"da39a3ee5e6b4b0d3255bfef95601890afd80709\n" +
		"\"5d41402abc4b2a76b9719d911017c592\",\"other\",\"file.txt\"\n" +
		"E52CAC67419A9A224A3B108F3FA6CB6D\n" +
		"\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	loadPayload, errObj := unwrapPair(t, HashsetLoad(stringObj(path)))
	if errObj != nil {
		t.Fatalf("hashset_load error: %s", errObj.Inspect())
	}
	lh := loadPayload.(*object.Hash)
	handle := lh.Pairs[(&object.String{Value: "handle"}).HashKey()].Value.(*object.String).Value
	count := lh.Pairs[(&object.String{Value: "count"}).HashKey()].Value.(*object.Integer).Value
	if count != 3 {
		t.Fatalf("expected 3 hashes loaded (header/comment/blank skipped), got %d", count)
	}

	contains := func(h string) bool {
		payload, errObj := unwrapPair(t, HashsetContains(stringObj(handle), stringObj(h)))
		if errObj != nil {
			t.Fatalf("hashset_contains error: %s", errObj.Inspect())
		}
		return payload.(*object.Boolean).Value
	}

	if !contains("da39a3ee5e6b4b0d3255bfef95601890afd80709") {
		t.Fatal("plain sha1 should be present")
	}
	// case-insensitive lookup + CSV-loaded hash.
	if !contains("5D41402ABC4B2A76B9719D911017C592") {
		t.Fatal("CSV-first-field hash should be present (case-insensitive)")
	}
	// uppercase-in-file hash found via lowercase query.
	if !contains("e52cac67419a9a224a3b108f3fa6cb6d") {
		t.Fatal("uppercase-in-file hash should be present")
	}
	if contains("ffffffffffffffffffffffffffffffff") {
		t.Fatal("unknown hash should not be present")
	}

	// close, then a lookup on the freed handle errors.
	if _, errObj := unwrapPair(t, HashsetClose(stringObj(handle))); errObj != nil {
		t.Fatalf("hashset_close error: %s", errObj.Inspect())
	}
	if _, errObj := unwrapPair(t, HashsetContains(stringObj(handle), stringObj("da39a3ee5e6b4b0d3255bfef95601890afd80709"))); errObj == nil {
		t.Fatal("lookup after close should error")
	}
}

func TestHashsetErrors(t *testing.T) {
	if _, errObj := unwrapPair(t, HashsetLoad(stringObj(filepath.Join(t.TempDir(), "nope")))); errObj == nil {
		t.Fatal("loading a missing file should error")
	}
	if _, errObj := unwrapPair(t, HashsetContains(stringObj("hashset-does-not-exist"), stringObj("abcd1234"))); errObj == nil {
		t.Fatal("contains on invalid handle should error")
	}
}
