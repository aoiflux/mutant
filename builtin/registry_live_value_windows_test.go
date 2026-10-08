//go:build windows

package builtin

import (
	"testing"

	"golang.org/x/sys/windows/registry"

	"mutant/object"
)

// M26-NET-004. readLiveRegistryValue mapped every GetValue error, including
// ERROR_FILE_NOT_FOUND for a value that is simply not there, to an entry of
// type REG_NONE with empty data:
//
//	_, valType, err := k.GetValue(name, nil)
//	if err != nil && err != registry.ErrShortBuffer {
//		return regEntry{name: displayName, typ: "REG_NONE", data: stringObj("")}
//	}
//
// and getValue handed that entry back with a nil error. So reg_get_value on the
// live registry answered "yes, an empty REG_NONE" for every name ever asked,
// while the JSON and hive-file backends answered "value not found: <name>" for
// the same question. "Does the Run key hold value X?" came back yes for any X.
//
// REG_NONE values do exist -- HKCR\.txt\OpenWithProgids has them -- so absence
// was not merely unreported, it was indistinguishable from a real present
// value. That is what makes this worse than a missing error.
//
// The typed getters' errors were discarded too, with `s, _, _ :=`, so a value
// deleted or retyped between reading its type and reading its data came back as
// a zero value of whatever type the first call saw.
//
// These tests are Windows-only because the backend is, and they create their
// own key under HKCU rather than reading whatever the host happens to have:
// a test that depends on this machine's registry contents is not a test. The
// key is removed again in Cleanup, including when the test fails.
//
// One case is deliberately not covered: a value of type REG_NONE itself.
// x/sys/windows/registry has no generic setter -- SetStringValue,
// SetBinaryValue and the rest all write a known type -- so REG_NONE cannot be
// created from Go here. The discrimination that matters is present-and-empty
// against not-present, and an empty REG_SZ and a zero-length REG_BINARY make
// that same distinction, so both are used below.

const liveRegTestSubKey = `Software\MutantReview-M26-NET-004`

// liveRegistryFixture creates the test key, writes the values the tests read,
// and returns the spec to open it with.
func liveRegistryFixture(t *testing.T) string {
	t.Helper()

	k, _, err := registry.CreateKey(registry.CURRENT_USER, liveRegTestSubKey, registry.ALL_ACCESS)
	if err != nil {
		t.Skipf("cannot create HKCU\\%s, so the live backend cannot be tested here: %v",
			liveRegTestSubKey, err)
	}
	t.Cleanup(func() {
		_ = k.Close()
		_ = registry.DeleteKey(registry.CURRENT_USER, liveRegTestSubKey)
	})

	if err := k.SetStringValue("Present", "a value"); err != nil {
		t.Fatalf("SetStringValue: %v", err)
	}
	if err := k.SetStringValue("PresentButEmpty", ""); err != nil {
		t.Fatalf("SetStringValue(empty): %v", err)
	}
	if err := k.SetBinaryValue("PresentButZeroBytes", []byte{}); err != nil {
		t.Fatalf("SetBinaryValue(empty): %v", err)
	}

	return `HKCU\` + liveRegTestSubKey
}

// TestTheLiveRegistryReportsAMissingValueAsMissing is the row, and it asserts
// the exact message, because the complaint is that the live backend disagreed
// with the other two. After the fix all three call errRegValueNotFound, so the
// agreement is by construction; this test is what notices if that is undone.
func TestTheLiveRegistryReportsAMissingValueAsMissing(t *testing.T) {
	backend, err := openLiveRegistry(liveRegistryFixture(t))
	if err != nil {
		t.Fatalf("openLiveRegistry: %v", err)
	}
	defer backend.close()

	const missing = "NoSuchValue-M26-NET-004"
	entry, err := backend.getValue("", missing)
	if err == nil {
		t.Fatalf("a value that does not exist came back as {type:%s data:%v} with no error",
			entry.typ, entry.data)
	}
	if want := errRegValueNotFound(missing).Error(); err.Error() != want {
		t.Errorf("the live backend says %q; every backend must say %q", err.Error(), want)
	}
}

// TestTheLiveRegistryStillReturnsAValueThatIsThere is the guard against the
// obvious over-correction: refusing everything would also make absence
// unambiguous.
func TestTheLiveRegistryStillReturnsAValueThatIsThere(t *testing.T) {
	backend, err := openLiveRegistry(liveRegistryFixture(t))
	if err != nil {
		t.Fatalf("openLiveRegistry: %v", err)
	}
	defer backend.close()

	entry, err := backend.getValue("", "Present")
	if err != nil {
		t.Fatalf("a value that is there reported an error: %v", err)
	}
	if entry.typ != "REG_SZ" {
		t.Errorf("type = %q, want REG_SZ", entry.typ)
	}
	str, ok := entry.data.(*object.String)
	if !ok {
		t.Fatalf("data is not a STRING. got=%T", entry.data)
	}
	if str.Value != "a value" {
		t.Errorf("data = %q, want %q", str.Value, "a value")
	}
}

// TestTheLiveRegistryTellsAnEmptyValueFromAMissingOne is the distinction the
// row is actually about. Both of these used to be indistinguishable from each
// other and from every name that was never there.
func TestTheLiveRegistryTellsAnEmptyValueFromAMissingOne(t *testing.T) {
	backend, err := openLiveRegistry(liveRegistryFixture(t))
	if err != nil {
		t.Fatalf("openLiveRegistry: %v", err)
	}
	defer backend.close()

	for _, c := range []struct {
		name string
		typ  string
	}{
		{"PresentButEmpty", "REG_SZ"},
		{"PresentButZeroBytes", "REG_BINARY"},
	} {
		t.Run(c.name, func(t *testing.T) {
			entry, err := backend.getValue("", c.name)
			if err != nil {
				t.Fatalf("an empty value that is there reported an error: %v", err)
			}
			if entry.typ != c.typ {
				t.Errorf("type = %q, want %q", entry.typ, c.typ)
			}
		})
	}
}

// TestTheLiveRegistryListsTheValuesItHas covers the enumeration path, which
// calls the same helper. It also pins the decision that goes with the fix: a
// value that vanishes between being listed and being read now fails the whole
// call rather than being dropped from the list, because a list presented as
// complete while silently short is the same defect as this row one level up.
// That race cannot be staged here, so what this test states is the ordinary
// case -- every value asked for comes back.
func TestTheLiveRegistryListsTheValuesItHas(t *testing.T) {
	backend, err := openLiveRegistry(liveRegistryFixture(t))
	if err != nil {
		t.Fatalf("openLiveRegistry: %v", err)
	}
	defer backend.close()

	entries, err := backend.enumValues("")
	if err != nil {
		t.Fatalf("enumValues: %v", err)
	}

	want := map[string]bool{"Present": false, "PresentButEmpty": false, "PresentButZeroBytes": false}
	for _, e := range entries {
		if _, ok := want[e.name]; ok {
			want[e.name] = true
		}
		if e.typ == "REG_NONE" {
			t.Errorf("value %q came back as REG_NONE; no value written here has that type", e.name)
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("value %q was written but not listed", name)
		}
	}
}
