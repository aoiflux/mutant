package security

import (
	"path/filepath"
	"strings"
	"testing"
)

// An account entry with no home directory, or a relative one, would put the
// keystore under whatever directory Mutant started in, so it is refused.
func TestAnAccountWithoutAnAbsoluteHomeIsRefused(t *testing.T) {
	home := t.TempDir()
	got, err := usableHomeDir("uid 1000", home+string(filepath.Separator))
	if err != nil || got != home {
		t.Fatalf("usableHomeDir(%q) = %q, %v; want %q, nil", home+string(filepath.Separator), got, err, home)
	}

	for _, tc := range []struct{ dir, want string }{
		{"", "records no home directory for uid 1000"},
		{"relative/home", "that is not absolute"},
	} {
		got, err := usableHomeDir("uid 1000", tc.dir)
		if err == nil || !strings.Contains(err.Error(), tc.want) || got != "" {
			t.Fatalf("usableHomeDir(%q) = %q, %v; want a refusal containing %q", tc.dir, got, err, tc.want)
		}
	}
}

// On Linux the keystore's home directory comes from /etc/passwd read by
// passwdHomeDir, because os/user answers for the caller's own uid from $HOME.
// It must read the file as os/user does, or an entry os/user would skip -- a
// comment, a NIS inclusion, a short or malformed line -- could name the home.
func TestThePasswdFileIsReadAsOsUserReadsIt(t *testing.T) {
	passwd := strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"# kevin:x:1005:1006::/home/commented:/bin/sh",
		"+nis:x:1005:1006::/home/nis-plus:/bin/sh",
		"-nis:x:1005:1006::/home/nis-minus:/bin/sh",
		"short:x:1005:1006:/home/short",
		":x:1005:1006::/home/noname:/bin/sh",
		"badgid:x:1005:staff::/home/badgid:/bin/sh",
		"",
		"  kevin:x:1005:1006:Kevin,,,:/home/kevin:/usr/bin/zsh\r",
		"later:x:1005:1006::/home/later:/bin/sh",
		"other:x:1006:1006::/home/other",
	}, "\n")

	for _, tc := range []struct {
		uid, home string
		found     bool
	}{
		{"0", "/root", true},
		{"1005", "/home/kevin", true},
		{"1006", "", false},
		{"01005", "", false},
		{"4242", "", false},
	} {
		home, found := passwdHomeDir([]byte(passwd), tc.uid)
		if home != tc.home || found != tc.found {
			t.Errorf("passwdHomeDir(uid %s) = %q, %v; want %q, %v", tc.uid, home, found, tc.home, tc.found)
		}
	}
}
