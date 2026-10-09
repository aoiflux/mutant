package builtin

// Regression tests for six artifact parsers that answered confidently and
// wrongly: M26-ART-003, M26-ART-012, M26-ART-019, M26-ART-020, M26-ART-021 and
// M26-ART-022.
//
// Each expectation here is written from the specification or the reference
// implementation the row cites -- MS-SHLLINK for the link flags, libscca and
// PECmd for the prefetch strides, Mandiant ShimCacheParser for the three
// AppCompatCache layouts, Chromium's DownloadState for the download states, and
// the Sleuth Kit bodyfile format -- and not from the table it is checking. A
// test that reads its expectation out of the code under test would have passed
// against every one of these defects.

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

// filetimeForUnix is the FILETIME for a unix second by the definition: 100ns
// ticks since 1601-01-01, which is 11644473600 seconds before the unix epoch.
// Written out rather than taken from filetimeToUnix, which is on the path these
// tests are checking.
func filetimeForUnix(unix int64) uint64 {
	return uint64((unix + 11644473600) * 10000000)
}

// ---------------------------------------------------------------- M26-ART-012

// TestLinkFlagsMatchTheSpecification pins every LinkFlags bit to its name.
//
// The table had the names from 0x1000 up shifted one bit, so a link that runs
// as another user reported HasDarwinID and a link with a Darwin ID reported
// nothing, and eleven of the twenty-seven flags were absent entirely. Both
// directions are checked: a bit that decodes to the wrong name, and a name the
// specification does not have.
func TestLinkFlagsMatchTheSpecification(t *testing.T) {
	// MS-SHLLINK 2.1.1, in document order. Unused1 and Unused2 are named there
	// and are decoded like the rest.
	spec := []struct {
		bit  uint32
		name string
	}{
		{0x00000001, "HasLinkTargetIDList"},
		{0x00000002, "HasLinkInfo"},
		{0x00000004, "HasName"},
		{0x00000008, "HasRelativePath"},
		{0x00000010, "HasWorkingDir"},
		{0x00000020, "HasArguments"},
		{0x00000040, "HasIconLocation"},
		{0x00000080, "IsUnicode"},
		{0x00000100, "ForceNoLinkInfo"},
		{0x00000200, "HasExpString"},
		{0x00000400, "RunInSeparateProcess"},
		{0x00000800, "Unused1"},
		{0x00001000, "HasDarwinID"},
		{0x00002000, "RunAsUser"},
		{0x00004000, "HasExpIcon"},
		{0x00008000, "NoPidlAlias"},
		{0x00010000, "Unused2"},
		{0x00020000, "RunWithShimLayer"},
		{0x00040000, "ForceNoLinkTrack"},
		{0x00080000, "EnableTargetMetadata"},
		{0x00100000, "DisableLinkPathTracking"},
		{0x00200000, "DisableKnownFolderTracking"},
		{0x00400000, "DisableKnownFolderAlias"},
		{0x00800000, "AllowLinkToLink"},
		{0x01000000, "UnaliasOnSave"},
		{0x02000000, "PreferEnvironmentPath"},
		{0x04000000, "KeepLocalIDListForUNCTarget"},
	}

	// Each bit on its own decodes to exactly its own name.
	for _, want := range spec {
		got := decodeLnkFlags(want.bit)
		if len(got) != 1 {
			t.Errorf("0x%08X decodes to %d names, want 1 (%s)", want.bit, len(got), want.name)
			continue
		}
		if s, ok := got[0].(*object.String); !ok || s.Value != want.name {
			t.Errorf("0x%08X decodes to %s, want %q", want.bit, got[0].Inspect(), want.name)
		}
	}

	// And the table holds these and nothing else, so a name cannot be added
	// against the specification without this failing.
	if len(lnkFlagNames) != len(spec) {
		t.Fatalf("the table has %d flags, MS-SHLLINK 2.1.1 names %d", len(lnkFlagNames), len(spec))
	}
	for i, want := range spec {
		if lnkFlagNames[i].bit != want.bit || lnkFlagNames[i].name != want.name {
			t.Errorf("table[%d] = {0x%08X, %q}, want {0x%08X, %q}",
				i, lnkFlagNames[i].bit, lnkFlagNames[i].name, want.bit, want.name)
		}
	}

	// All twenty-seven at once, and nothing lost in the middle.
	var all uint32
	for _, s := range spec {
		all |= s.bit
	}
	if got := decodeLnkFlags(all); len(got) != len(spec) {
		t.Errorf("every flag set decodes to %d names, want %d", len(got), len(spec))
	}

	// A bit above the named range is reported rather than dropped, because
	// link_flags sits in the same result and a list that accounts for less
	// than the number beside it is the defect this test is here for.
	got := decodeLnkFlags(0x80000000)
	if len(got) != 1 {
		t.Fatalf("an unnamed bit decodes to %d names, want 1", len(got))
	}
	if s, ok := got[0].(*object.String); !ok || s.Value != "Bit31" {
		t.Errorf("bit 31 decodes to %s, want \"Bit31\"", got[0].Inspect())
	}
}

// ---------------------------------------------------------------- M26-ART-003

// TestPrefetchVolumeStridePerVersion reads a second volume at each version.
//
// The stride was 104 below v26 and 96 from v26 up, which is right for v23 and
// v30 only. The v26 case is the one worth seeing: stepping 96 where the entries
// are 104 apart read the second volume's serial out of the middle of its own
// creation FILETIME, so the answer was a plausible eight-digit serial rather
// than an obvious zero.
func TestPrefetchVolumeStridePerVersion(t *testing.T) {
	// libscca, and PECmd's three readers: Version17.cs steps 40,
	// Version26.cs steps 104, Version30or31.cs steps 96.
	for _, tt := range []struct {
		version uint32
		stride  int
	}{
		{17, 40},
		{23, 104},
		{26, 104},
		{30, 96},
		{31, 96},
	} {
		t.Run(fmt.Sprintf("v%d", tt.version), func(t *testing.T) {
			if got := prefetchVolumeStride(tt.version); got != tt.stride {
				t.Errorf("stride for v%d is %d, want %d", tt.version, got, tt.stride)
			}

			const volOff = 0x100
			data := make([]byte, volOff+2*tt.stride+64)
			binary.LittleEndian.PutUint32(data[0x6C:], volOff)
			binary.LittleEndian.PutUint32(data[0x70:], 2)
			for i, serial := range []uint32{0x11111111, 0x22222222} {
				base := volOff + i*tt.stride
				binary.LittleEndian.PutUint64(data[base+0x08:], filetimeForUnix(1600000000))
				binary.LittleEndian.PutUint32(data[base+0x10:], serial)
			}

			vols := parsePrefetchVolumes(data, tt.version)
			if len(vols) != 2 {
				t.Fatalf("parsed %d volumes, want 2", len(vols))
			}
			for i, want := range []string{"11111111", "22222222"} {
				if got := hStr(t, vols[i].(*object.Hash), "serial"); got != want {
					t.Errorf("volume %d serial = %q, want %q", i, got, want)
				}
			}
			for i := range vols {
				if got := hInt(t, vols[i].(*object.Hash), "created"); got != 1600000000 {
					t.Errorf("volume %d created = %d, want 1600000000", i, got)
				}
			}
		})
	}

	// A version with no stride reads no volumes rather than guessing at a
	// neighbour's. prefetch_parse carries on past an unrecognised version, so
	// this is reachable, and the version it declined is in the result beside
	// the empty array.
	if got := prefetchVolumeStride(99); got != 0 {
		t.Errorf("stride for an unknown version is %d, want 0", got)
	}
	data := make([]byte, 0x100+256)
	binary.LittleEndian.PutUint32(data[0x6C:], 0x100)
	binary.LittleEndian.PutUint32(data[0x70:], 2)
	if vols := parsePrefetchVolumes(data, 99); len(vols) != 0 {
		t.Errorf("an unknown version read %d volumes, want 0", len(vols))
	}
}

// ---------------------------------------------------------------- M26-ART-020

// TestBodyfileNameMayContainTheSeparator is the delimiter-injection case.
//
// Splitting on every pipe and indexing from the left let a filename supply the
// inode, the size and all four MAC times for its own row, so an attacker who
// chose a filename chose what the super-timeline said about that file.
func TestBodyfileNameMayContainTheSeparator(t *testing.T) {
	name := "/tmp/x|0|0|0|0|0|999|999|999|999"
	row := "d41d8cd98f00b204e9800998ecf8427e|" + name +
		"|12345-128-1|r/rrwxrwxrwx|0|0|1024|1600000000|1600000001|1600000002|1600000003"
	path := filepath.Join(t.TempDir(), "body.txt")
	if err := os.WriteFile(path, []byte(row+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	payload, errObj := unwrapPair(t, BodyfileParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("bodyfile_parse: %s", errObj.Inspect())
	}
	entries, ok := payload.(*object.Array)
	if !ok || len(entries.Elements) != 1 {
		t.Fatalf("want 1 entry, got %s", payload.Inspect())
	}
	e := entries.Elements[0].(*object.Hash)

	if got := hStr(t, e, "name"); got != name {
		t.Errorf("name = %q, want %q", got, name)
	}
	if got := hStr(t, e, "inode"); got != "12345-128-1" {
		t.Errorf("inode = %q, want \"12345-128-1\"", got)
	}
	for _, f := range []struct {
		field string
		want  int64
	}{
		{"size", 1024},
		{"atime", 1600000000},
		{"mtime", 1600000001},
		{"ctime", 1600000002},
		{"crtime", 1600000003},
	} {
		if got := hInt(t, e, f.field); got != f.want {
			t.Errorf("%s = %d, want %d -- the name supplied its own value", f.field, got, f.want)
		}
	}

	// An ordinary row is unchanged, including a name with no separator in it.
	plain := "0|/etc/passwd|9-128-1|r/rrw-r--r--|0|0|2048|1700000000|1700000100|1700000100|1700000000"
	path2 := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(path2, []byte(plain+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload2, errObj2 := unwrapPair(t, BodyfileParse(stringObj(path2)))
	if errObj2 != nil {
		t.Fatalf("bodyfile_parse: %s", errObj2.Inspect())
	}
	e2 := payload2.(*object.Array).Elements[0].(*object.Hash)
	if got := hStr(t, e2, "name"); got != "/etc/passwd" {
		t.Errorf("plain name = %q, want \"/etc/passwd\"", got)
	}
	if got := hInt(t, e2, "mtime"); got != 1700000100 {
		t.Errorf("plain mtime = %d, want 1700000100", got)
	}
}

// TestBodyfileRefusesAFileWithNoRows is the false success beside it: a file in
// some other format parsed to an empty array and no error.
func TestBodyfileRefusesAFileWithNoRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notabodyfile.csv")
	if err := os.WriteFile(path, []byte("date,host,event\n2026-01-01,a,login\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, errObj := unwrapPair(t, BodyfileParse(stringObj(path)))
	if errObj == nil {
		t.Fatal("a file with no bodyfile row in it parsed successfully")
	}

	// An empty file is empty, not malformed: there is nothing to report.
	empty := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(empty, []byte("# only a comment\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload, errObj := unwrapPair(t, BodyfileParse(stringObj(empty)))
	if errObj != nil {
		t.Fatalf("a comment-only bodyfile should parse to no entries, got %s", errObj.Inspect())
	}
	if arr, ok := payload.(*object.Array); !ok || len(arr.Elements) != 0 {
		t.Fatalf("want an empty array, got %s", payload.Inspect())
	}
}

// ---------------------------------------------------------------- M26-ART-022

// shimcacheBlob builds an AppCompatCache blob in one of the three layouts, per
// Mandiant ShimCacheParser: the header size selects the layout and the magic
// selects whether the Win8 package data is present.
func shimcacheBlob(headerSize int, magic, path string, unix int64) []byte {
	var utf16 []byte
	for _, r := range path {
		utf16 = append(utf16, byte(r), 0)
	}
	var entry []byte
	entry = binary.LittleEndian.AppendUint16(entry, uint16(len(utf16)))
	entry = append(entry, utf16...)
	if headerSize == 0x80 {
		if magic == "00ts" {
			entry = binary.LittleEndian.AppendUint16(entry, 0) // package data length
		}
		entry = binary.LittleEndian.AppendUint32(entry, 0) // flags
		entry = binary.LittleEndian.AppendUint32(entry, 0) // unknown
	}
	entry = binary.LittleEndian.AppendUint64(entry, filetimeForUnix(unix))
	entry = binary.LittleEndian.AppendUint32(entry, 0) // data length

	blob := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(blob[0:4], uint32(headerSize))
	blob = append(blob, []byte(magic)...)
	blob = binary.LittleEndian.AppendUint32(blob, 0) // crc32
	blob = binary.LittleEndian.AppendUint32(blob, uint32(len(entry)))
	return append(blob, entry...)
}

// TestShimcacheReadsTheVersionsItClaims covers the two the decoder refused.
//
// The refusal message named Win8 and Win8.1 as supported while refusing them,
// so the error was its own counterexample. Relaxing the header check alone
// would have been worse: both 0x80 layouts carry a flags word and an unknown
// word between the path and the FILETIME, so a Win8.1 entry read at the Win10
// layout returns a timestamp built out of the flags.
func TestShimcacheReadsTheVersionsItClaims(t *testing.T) {
	const wantPath = "C:/Windows/System32/evil.exe"
	for _, tt := range []struct {
		name       string
		headerSize int
		magic      string
		version    string
	}{
		{"win8", 0x80, "00ts", "win8"},
		{"win81", 0x80, "10ts", "win81"},
		{"win10", 0x30, "10ts", "win10"},
		{"win10 alternate header", 0x34, "10ts", "win10"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			entries, version, err := decodeShimcache(
				shimcacheBlob(tt.headerSize, tt.magic, wantPath, 1600000000))
			if err != nil {
				t.Fatalf("header 0x%x magic %s: %v", tt.headerSize, tt.magic, err)
			}
			if len(entries) != 1 {
				t.Fatalf("%d entries, want 1", len(entries))
			}
			if entries[0].path != wantPath {
				t.Errorf("path = %q, want %q", entries[0].path, wantPath)
			}
			// The timestamp is the assertion that the layout, and not only the
			// header check, was followed.
			if entries[0].lastModified != 1600000000 {
				t.Errorf("last_modified = %d, want 1600000000", entries[0].lastModified)
			}
			if version != tt.version {
				t.Errorf("version = %q, want %q", version, tt.version)
			}
		})
	}

	// Win8 package data is skipped rather than read as the flags.
	blob := shimcacheBlob(0x80, "00ts", wantPath, 1600000000)
	withPackage := func() []byte {
		var utf16 []byte
		for _, r := range wantPath {
			utf16 = append(utf16, byte(r), 0)
		}
		pkg := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		var entry []byte
		entry = binary.LittleEndian.AppendUint16(entry, uint16(len(utf16)))
		entry = append(entry, utf16...)
		entry = binary.LittleEndian.AppendUint16(entry, uint16(len(pkg)))
		entry = append(entry, pkg...)
		entry = binary.LittleEndian.AppendUint32(entry, 0)
		entry = binary.LittleEndian.AppendUint32(entry, 0)
		entry = binary.LittleEndian.AppendUint64(entry, filetimeForUnix(1600000000))
		entry = binary.LittleEndian.AppendUint32(entry, 0)
		out := make([]byte, 0x80)
		binary.LittleEndian.PutUint32(out[0:4], 0x80)
		out = append(out, []byte("00ts")...)
		out = binary.LittleEndian.AppendUint32(out, 0)
		out = binary.LittleEndian.AppendUint32(out, uint32(len(entry)))
		return append(out, entry...)
	}()
	if len(withPackage) == len(blob) {
		t.Fatal("the package-data fixture is the same size as the one without it")
	}
	entries, version, err := decodeShimcache(withPackage)
	if err != nil {
		t.Fatalf("win8 with package data: %v", err)
	}
	if len(entries) != 1 || entries[0].lastModified != 1600000000 {
		t.Fatalf("win8 with package data: %+v (version %q)", entries, version)
	}

	// A header that is none of the three is still refused, and the message no
	// longer names the versions it is refusing.
	bad := make([]byte, 0x40)
	binary.LittleEndian.PutUint32(bad[0:4], 0x44)
	_, _, err = decodeShimcache(bad)
	if err == nil {
		t.Fatal("an unknown header size parsed")
	}
}

// ---------------------------------------------------------------- M26-ART-021

// TestStdlibClassificationUsesTheMainModule covers the dotless module path.
//
// The test was "no dot in the first path segment", so `go mod init agent` made
// every package of the program being examined standard library, and go_symbols
// in user mode -- the mode that exists to show the program's own code -- showed
// main.main alone.
func TestStdlibClassificationUsesTheMainModule(t *testing.T) {
	for _, tt := range []struct {
		pkg        string
		mainModule string
		std        bool
	}{
		// The dotless module and its packages are the program's own code.
		{"agent", "agent", false},
		{"agent/core", "agent", false},
		{"agent/internal/stealer", "agent", false},
		// A domain-qualified module, which the old test did classify right.
		{"github.com/x/y", "github.com/x/y", false},
		{"github.com/x/y/z", "github.com/x/y", false},
		// A dependency is not the main module and not stdlib.
		{"github.com/other/dep", "agent", false},
		// Dotless and neither the main module nor a standard library name.
		{"evil", "agent", false},
		{"evil/core", "agent", false},
		// The standard library, with and without build information.
		{"fmt", "agent", true},
		{"net/http", "agent", true},
		{"runtime", "", true},
		{"internal/abi", "", true},
		{"vendor/golang.org/x/net/dns/dnsmessage", "", true},
		// main is the program, and an unnamed package cannot be attributed.
		{"main", "agent", false},
		{"", "agent", true},
		// A module whose path collides with a standard library name is still
		// the program's own code, because the binary says so.
		{"net", "net", false},
		{"net/resolver", "net", false},
	} {
		t.Run(tt.pkg+"|"+tt.mainModule, func(t *testing.T) {
			if got := isStdlibPackage(tt.pkg, tt.mainModule); got != tt.std {
				t.Errorf("isStdlibPackage(%q, %q) = %v, want %v",
					tt.pkg, tt.mainModule, got, tt.std)
			}
		})
	}
}

// TestStdlibTopLevelIsTheRealList guards the list against drift.
//
// It is `go list std` cut to its first path segment, so a name that is not a
// standard library top-level name does not belong in it. The three the
// toolchain uses but a program does not import are checked by name because
// they are the ones a reader would think were mistakes.
func TestStdlibTopLevelIsTheRealList(t *testing.T) {
	for _, name := range []string{"internal", "vendor", "go", "runtime", "unsafe"} {
		if !stdlibTopLevel[name] {
			t.Errorf("%q is a standard library top-level name and is missing", name)
		}
	}
	// Names that have never been in it, one of which (arena) was removed from
	// Go and one of which (builtin) is documentation only.
	for _, name := range []string{"agent", "github.com", "arena", "builtin", "main", ""} {
		if stdlibTopLevel[name] {
			t.Errorf("%q is in the standard library list and should not be", name)
		}
	}
}

// ---------------------------------------------------------------- M26-ART-019

// TestChromeDownloadStatesMatchChromium pins the state map.
//
// INTERRUPTED is 4. The map had 3, which is BUG_140687, a value Chromium
// retired, so an interrupted download -- a transfer that stopped partway, the
// state worth noticing -- reported "unknown".
func TestChromeDownloadStatesMatchChromium(t *testing.T) {
	for state, want := range map[int64]string{
		0: "in_progress",
		1: "complete",
		2: "cancelled",
		3: "interrupted", // legacy BUG_140687
		4: "interrupted", // INTERRUPTED
	} {
		if got := chromeDownloadStates[state]; got != want {
			t.Errorf("state %d maps to %q, want %q", state, got, want)
		}
	}
	// A state Chromium does not define is not given a name here, so the caller
	// is told "unknown" rather than a neighbour's meaning.
	for _, state := range []int64{5, 99, -1} {
		if got, ok := chromeDownloadStates[state]; ok {
			t.Errorf("state %d maps to %q; it has no meaning to map", state, got)
		}
	}
}

// TestBrowserDownloadsReportsTheFileSource is the defect end to end.
//
// A file fetched from a link in webmail: the download came from
// cdn.evil.example and the user was reading their inbox. "url" held the inbox,
// so the origin of the file -- the indicator the record exists to carry -- was
// the page the user happened to have open, and the interrupted transfer
// reported "unknown".
func TestBrowserDownloadsReportsTheFileSource(t *testing.T) {
	stmts := "CREATE TABLE downloads (id INTEGER PRIMARY KEY, tab_url TEXT, tab_referrer_url TEXT, " +
		"site_url TEXT, target_path TEXT, total_bytes INTEGER, received_bytes INTEGER, " +
		"start_time INTEGER, end_time INTEGER, state INTEGER, mime_type TEXT);" +
		"CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT);" +
		"INSERT INTO downloads VALUES (7, 'https://mail.example/inbox', 'https://mail.example/msg/1', " +
		"'https://mail.example/', '/home/u/invoice.exe', 4096, 2048, " +
		itoa(webkitTime(1600000000)) + ", " + itoa(webkitTime(1600000005)) + ", 4, " +
		"'application/x-msdownload');" +
		// Two hops: a shortener, then where the bytes actually came from.
		"INSERT INTO downloads_url_chains VALUES (7, 0, 'https://short.example/a1b2');" +
		"INSERT INTO downloads_url_chains VALUES (7, 1, 'https://cdn.evil.example/payload.exe');"
	path := makeDBWith(t, stmts)

	entries := browserEntries(t, BrowserDownloads(stringObj(path)), "chrome")
	if len(entries.Elements) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries.Elements))
	}
	e := entries.Elements[0].(*object.Hash)

	// The file's source, not the page the user was on.
	if got := hStr(t, e, "url"); got != "https://cdn.evil.example/payload.exe" {
		t.Errorf("url = %q, want the last hop of the chain", got)
	}
	// And the page is still available, under its own name.
	if got := hStr(t, e, "tab_url"); got != "https://mail.example/inbox" {
		t.Errorf("tab_url = %q, want the inbox", got)
	}
	if got := hStr(t, e, "referrer"); got != "https://mail.example/msg/1" {
		t.Errorf("referrer = %q", got)
	}
	if got := hStr(t, e, "site_url"); got != "https://mail.example/" {
		t.Errorf("site_url = %q", got)
	}
	// Every hop, in order, because which one is the indicator depends on the
	// question being asked.
	chain, ok := hashValueByKey(e, "url_chain").(*object.Array)
	if !ok || len(chain.Elements) != 2 {
		t.Fatalf("url_chain = %s, want two hops", hashValueByKey(e, "url_chain").Inspect())
	}
	for i, want := range []string{"https://short.example/a1b2", "https://cdn.evil.example/payload.exe"} {
		if s, ok := chain.Elements[i].(*object.String); !ok || s.Value != want {
			t.Errorf("url_chain[%d] = %s, want %q", i, chain.Elements[i].Inspect(), want)
		}
	}
	if got := hStr(t, e, "state"); got != "interrupted" {
		t.Errorf("state = %q, want \"interrupted\" (Chromium state 4)", got)
	}
}

// TestBrowserDownloadsWithoutTheChainTable is the older schema.
//
// downloads_url_chains arrived in Chrome 26 and tab_referrer_url later still.
// A database without them is read for what it has rather than failed, and the
// empty url_chain says the chain was not there to read -- which is a different
// statement from a download that had no redirects.
func TestBrowserDownloadsWithoutTheChainTable(t *testing.T) {
	stmts := "CREATE TABLE downloads (id INTEGER PRIMARY KEY, tab_url TEXT, target_path TEXT, " +
		"total_bytes INTEGER, received_bytes INTEGER, start_time INTEGER, end_time INTEGER, " +
		"state INTEGER, mime_type TEXT);" +
		"INSERT INTO downloads VALUES (1, 'https://dl.example/file.zip', '/tmp/file.zip', 1000, 1000, " +
		itoa(webkitTime(1600000000)) + ", " + itoa(webkitTime(1600000005)) + ", 1, 'application/zip');"
	path := makeDBWith(t, stmts)

	entries := browserEntries(t, BrowserDownloads(stringObj(path)), "chrome")
	if len(entries.Elements) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries.Elements))
	}
	e := entries.Elements[0].(*object.Hash)
	if got := hStr(t, e, "url"); got != "https://dl.example/file.zip" {
		t.Errorf("url = %q, want the tab_url this schema does hold", got)
	}
	if chain, ok := hashValueByKey(e, "url_chain").(*object.Array); !ok || len(chain.Elements) != 0 {
		t.Errorf("url_chain should be empty where the table is absent")
	}
	// The absent columns are empty rather than an error.
	if got := hStr(t, e, "referrer"); got != "" {
		t.Errorf("referrer = %q, want empty on a schema without the column", got)
	}
}
