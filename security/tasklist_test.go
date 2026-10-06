package security

import "testing"

// TestWindowsImageNamesReadsTheQuotedField pins the three properties of the
// listing that made tasklist's table form unreadable: a name with spaces in it,
// a name past the table column's 25 characters, and the INFO: line tasklist
// prints in place of an empty listing.
func TestWindowsImageNamesReadsTheQuotedField(t *testing.T) {
	out := `"System Idle Process","0","Services","0","8 K"` + "\r\n" +
		`"ArmouryCrate.UserSessionHelper.exe","1234","Console","1","5,000 K"` + "\r\n" +
		`"VMToolsd.exe","2345","Services","0","1,024 K"` + "\r\n" +
		"INFO: No tasks are running which match the specified criteria." + "\r\n" +
		"\r\n"

	names := windowsImageNames(out)
	if len(names) != 3 {
		t.Fatalf("expected 3 image names, got %d: %v", len(names), names)
	}
	for _, want := range []string{
		"system idle process",
		"armourycrate.usersessionhelper.exe",
		"vmtoolsd.exe",
	} {
		if _, ok := names[want]; !ok {
			t.Fatalf("expected %q in the listing, got %v", want, names)
		}
	}
}

// TestWindowsImageNamesOnNothingUseful covers the inputs a failed or empty
// listing gives, because the detector reads the result either way and a name
// invented from a header or a blank line would be a signal that nothing saw.
func TestWindowsImageNamesOnNothingUseful(t *testing.T) {
	for _, out := range []string{
		"",
		"\r\n\r\n",
		"INFO: No tasks are running which match the specified criteria.\r\n",
		`""` + "\r\n",
		`"   "` + "\r\n",
	} {
		if names := windowsImageNames(out); len(names) != 0 {
			t.Fatalf("expected no image names from %q, got %v", out, names)
		}
	}
}

// TestWindowsImageNamesOnAMalformedLine records what a line that is not a
// tasklist row actually produces, rather than what it ought to. It is read as
// far as its quotes allow, which can leave a string that is not an image name,
// and that is harmless because a name from the listing is only ever compared
// against a fixed list of targets and never the other way round.
func TestWindowsImageNamesOnAMalformedLine(t *testing.T) {
	names := windowsImageNames(`"unterminated,"1234"` + "\r\n")
	if _, ok := names["unterminated,"]; !ok {
		t.Fatalf("expected the quoted run to be read as it stands, got %v", names)
	}
	if hasAnyImageName(names, []string{"vmwp.exe", "vmtoolsd.exe", "bash.exe"}) {
		t.Fatalf("expected a malformed line to match no target, got %v", names)
	}
}

// TestHasAnyImageNameMatchesWholeNames is the defect this file exists for. Each
// target below is held somewhere inside a name in the listing without being
// that name, and each one either halted the run or, for the Hyper-V host
// names, switched every Hyper-V guest signal the detector has off.
func TestHasAnyImageNameMatchesWholeNames(t *testing.T) {
	names := windowsImageNames(
		`"svchost.exe","1","Services","0","1 K"` + "\r\n" +
			`"notvmwp.exe","2","Services","0","1 K"` + "\r\n" +
			`"myvmtoolsd.exe","3","Services","0","1 K"` + "\r\n" +
			`"vmms.exe.bak","4","Services","0","1 K"` + "\r\n" +
			`"gitbash.exe","5","Console","1","1 K"` + "\r\n")

	for _, target := range []string{
		"vmwp.exe", "vmtoolsd.exe", "vmms.exe", "bash.exe",
		"svchost", "host.exe", "svchost.ex",
	} {
		if hasAnyImageName(names, []string{target}) {
			t.Fatalf("expected %q not to be found in %v", target, names)
		}
	}

	if !hasAnyImageName(names, []string{"explorer.exe", "svchost.exe"}) {
		t.Fatalf("expected svchost.exe to be found in %v", names)
	}
	if hasAnyImageName(names, nil) {
		t.Fatalf("expected an empty target list to match nothing")
	}
}
