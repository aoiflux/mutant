package builtin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

func plistHash(t *testing.T, path string) *object.Hash {
	t.Helper()
	payload, errObj := unwrapPair(t, PlistParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("plist_parse error: %s", errObj.Inspect())
	}
	h, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("plist root should be a HASH, got %T (%s)", payload, payload.Inspect())
	}
	return h
}

func TestPlistParseXML(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>Name</key><string>Mutant</string>
  <key>Count</key><integer>42</integer>
  <key>Enabled</key><true/>
  <key>Ratio</key><real>1.5</real>
  <key>Tags</key>
  <array><string>a</string><string>b</string></array>
</dict>
</plist>`
	dir := t.TempDir()
	path := filepath.Join(dir, "info.plist")
	if err := os.WriteFile(path, []byte(xml), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	h := plistHash(t, path)
	if hStr(t, h, "Name") != "Mutant" {
		t.Fatalf("Name = %q", hStr(t, h, "Name"))
	}
	if hInt(t, h, "Count") != 42 {
		t.Fatalf("Count = %d", hInt(t, h, "Count"))
	}
	if !hBoolAt(t, h, "Enabled") {
		t.Fatal("Enabled should be true")
	}
	ratio, ok := hashValueByKey(h, "Ratio").(*object.Float)
	if !ok || ratio.Value != 1.5 {
		t.Fatalf("Ratio = %v", hashValueByKey(h, "Ratio").Inspect())
	}
	tags, ok := hashValueByKey(h, "Tags").(*object.Array)
	if !ok || len(tags.Elements) != 2 || tags.Elements[0].(*object.String).Value != "a" {
		t.Fatalf("Tags = %s", hashValueByKey(h, "Tags").Inspect())
	}
}

func TestPlistParseBinary(t *testing.T) {
	// Hand-crafted bplist00 for {"a": 1}.
	buf := []byte("bplist00")
	buf = append(buf, 0xD1, 0x01, 0x02) // obj0 @8: dict count=1, keyref=1, valref=2
	buf = append(buf, 0x51, 'a')        // obj1 @11: ASCII string "a"
	buf = append(buf, 0x10, 0x01)       // obj2 @13: int 1
	buf = append(buf, 0x08, 0x0B, 0x0D) // offset table @15: [8,11,13]
	trailer := make([]byte, 32)
	trailer[6] = 1 // offsetIntSize
	trailer[7] = 1 // objectRefSize
	binary.BigEndian.PutUint64(trailer[8:16], 3)   // numObjects
	binary.BigEndian.PutUint64(trailer[16:24], 0)  // topObject
	binary.BigEndian.PutUint64(trailer[24:32], 15) // offsetTableOffset
	buf = append(buf, trailer...)

	dir := t.TempDir()
	path := filepath.Join(dir, "data.plist")
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	h := plistHash(t, path)
	if hInt(t, h, "a") != 1 {
		t.Fatalf("binary plist a = %s", h.Inspect())
	}

	// Truncated binary plist errors (or fails gracefully), not panics.
	badPath := filepath.Join(dir, "bad.plist")
	_ = os.WriteFile(badPath, []byte("bplist00short"), 0644)
	if _, errObj := unwrapPair(t, PlistParse(stringObj(badPath))); errObj == nil {
		t.Fatal("truncated binary plist should error")
	}
}
