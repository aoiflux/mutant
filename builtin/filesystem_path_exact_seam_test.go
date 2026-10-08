package builtin

import (
	"strings"
	"testing"
)

// normalizePOSIXFSPath keeps a backslash as a name byte and trims nothing, and
// still cannot be walked above the volume root (M26-FS1-008).
func TestAPOSIXPathKeepsItsBackslashesAndStaysInsideTheVolume(t *testing.T) {
	for in, want := range map[string]string{
		`/a\b`: `/a\b`,
		`a\b`:  `/a\b`,
		`/etc/systemd/system/mnt-data\x2dbackup.mount`: `/etc/systemd/system/mnt-data\x2dbackup.mount`,
		"/x ":     "/x ",
		" x":      "/ x",
		`\..`:     `/\..`,
		"":        "/",
		"/a/../b": "/b",
	} {
		if got := normalizePOSIXFSPath(in); got != want {
			t.Errorf("normalizePOSIXFSPath(%q) = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{"..", "../..", "/../etc", "a/../../.."} {
		if got := normalizePOSIXFSPath(in); !strings.HasPrefix(got, "/") || strings.HasPrefix(got, "/..") {
			t.Errorf("normalizePOSIXFSPath(%q) = %q, want an absolute path inside the volume", in, got)
		}
	}
	// The Windows-family normaliser no longer trims either.
	if got := normalizeFSPath("/x "); got != "/x " {
		t.Errorf("normalizeFSPath trimmed a name's trailing space: %q", got)
	}
}

// libhfs trims a path's ends before splitting it, so a name ending in a space
// is refused rather than looked up without it.
func TestAnHFSPathEndingInWhitespaceIsRefused(t *testing.T) {
	for _, p := range []string{"/x ", "/dir/file\t", "/a\v"} {
		if err := hfsPathAddressable(p); err == nil {
			t.Errorf("hfsPathAddressable(%q) accepted a path libhfs would trim", p)
		}
	}
	for _, p := range []string{"/", "/x", "/ x", `/a\b`, "/a b/c"} {
		if err := hfsPathAddressable(p); err != nil {
			t.Errorf("hfsPathAddressable(%q): %v", p, err)
		}
	}
}
