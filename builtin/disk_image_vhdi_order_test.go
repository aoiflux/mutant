package builtin

import (
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// TestDuplicateLinkWarningsComeInOneOrder is M26-FS1-016's regression test.
// Three link identities are each recorded by two images, so vhdi_discover
// warns three times -- and the warnings came from ranging over a map, so the
// same directory produced them in a different order from call to call.
func TestDuplicateLinkWarningsComeInOneOrder(t *testing.T) {
	dir := vhdFixtureDir(t)
	sector := make([]byte, vhdSectorSize)
	for i, pair := range []string{"a", "b", "c"} {
		var id [16]byte
		id[0] = byte(0xA0 + i)
		for _, n := range []string{"1", "2"} {
			writeFixedVHD(t, filepath.Join(dir, pair+n+".vhd"), sector, id)
		}
	}

	orders := map[string]int{}
	for call := 0; call < 40; call++ {
		payload, errObj := unwrapPair(t, VHDIDiscover(stringObj(dir)))
		if errObj != nil {
			t.Fatalf("vhdi_discover: %s", errObj.Inspect())
		}
		var order []string
		for _, w := range mustHashArrayValue(t, payload.(*object.Hash), "warnings") {
			warning := w.(*object.Hash)
			if mustHashStringValue(t, warning, "code") == vhdiWarnDuplicateLink {
				order = append(order, filepath.Base(mustHashStringValue(t, warning, "location")))
			}
		}
		if len(order) != 3 {
			t.Fatalf("call %d raised %d duplicate-link warnings, want 3: %v", call, len(order), order)
		}
		orders[strings.Join(order, ",")]++
	}
	if len(orders) != 1 {
		t.Fatalf("40 calls on one directory gave the warnings in %d orders: %v", len(orders), orders)
	}
}
