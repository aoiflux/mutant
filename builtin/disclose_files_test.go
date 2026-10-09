package builtin

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// checkFiles compares SHA256SUMS with the manifest, and it used to do so only
// where the two already named the same file: the comparison sat behind
// `if expected, listed := want[name]; listed && ...`. Four things followed from
// that one word, and there is a test here for each (M26-REC-029):
//
//   - a checksum line naming a file the manifest does not list was skipped in
//     silence;
//   - disclosure.json cannot appear in its own file list, so whatever SHA256SUMS
//     claimed the manifest hashed to was never compared with the manifest that
//     was there;
//   - nothing read the directory, so a file named in neither list was never
//     noticed;
//   - nothing walked the manifest's list, so an entry with no checksum line was
//     not noticed either.
//
// A SHA256SUMS naming entirely different files therefore agreed trivially, and
// the summary still read "all N files hash to the digests the manifest names".
//
// checkFiles had no tests at all before these. They drive it directly, through a
// discloseVerification built with nothing but a directory and a manifest, which
// is all it reads -- so they cost no record seal, no case key and no Argon2id
// derivation, and they run against the defective function as readily as the
// fixed one.

// discloseSumsDigest is the digest format custodyHashFile returns and
// bundleChecksums writes: lowercase hex.
func discloseSumsDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// discloseSumsPackage builds the shape disclose_bundle writes: the four
// artifacts the manifest lists, the manifest beside them, and a SHA256SUMS over
// all five.
//
// Five and not four, and not six: a manifest cannot carry its own digest, so the
// checksum file has one line more than the manifest has entries, and SHA256SUMS
// does not cover itself. A fix that simply required every checksum line to be
// named in the manifest would reject every package this build has ever written,
// which is why that shape is what the first test below pins.
//
// The lines are returned so that a test can corrupt exactly one thing and leave
// everything else consistent.
func discloseSumsPackage(t *testing.T) (dir string, manifest map[string]any, lines []string) {
	t.Helper()
	dir = t.TempDir()

	files := make([]any, 0, 4)
	for _, name := range []string{discloseRecordName, discloseGrantName, discloseProofName, discloseReportName} {
		body := []byte("the contents of " + name + ", which nothing here reads for meaning")
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		files = append(files, map[string]any{"name": name, "sha256": discloseSumsDigest(body)})
		lines = append(lines, discloseSumsDigest(body)+"  "+name)
	}

	document := []byte("{\"format\": \"mutant.disclosure\", \"files\": []}\n")
	if err := os.WriteFile(filepath.Join(dir, discloseManifestName), document, 0o600); err != nil {
		t.Fatalf("write %s: %v", discloseManifestName, err)
	}
	lines = append(lines, discloseSumsDigest(document)+"  "+discloseManifestName)

	manifest = map[string]any{"files": files}
	discloseSumsWrite(t, dir, lines)
	return dir, manifest, lines
}

// discloseSumsWrite writes SHA256SUMS in the format bundleChecksums produces:
// the hex, two spaces, the name, sorted.
func discloseSumsWrite(t *testing.T, dir string, lines []string) {
	t.Helper()
	sorted := make([]string, len(lines))
	copy(sorted, lines)
	sort.Strings(sorted)
	body := strings.Join(sorted, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, discloseChecksumsName), []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", discloseChecksumsName, err)
	}
}

// discloseSumsChecks runs checkFiles and returns its checks by name.
func discloseSumsChecks(t *testing.T, dir string, manifest map[string]any) map[string]discloseCheck {
	t.Helper()
	v := &discloseVerification{op: BuiltinNameDiscloseVerify, dir: dir, manifest: manifest}
	v.checkFiles()
	out := make(map[string]discloseCheck, len(v.checks))
	for _, check := range v.checks {
		out[check.name] = check
	}
	return out
}

// discloseSumsCheckNames runs checkFiles and returns the names it recorded, in
// the order it recorded them. discloseSumsChecks returns a map keyed by name and
// so cannot answer how many checks were recorded at all: two checks under one
// name would come back as one entry, and a path that recorded none would be
// indistinguishable from a path that recorded one of each.
func discloseSumsCheckNames(t *testing.T, dir string, manifest map[string]any) []string {
	t.Helper()
	v := &discloseVerification{op: BuiltinNameDiscloseVerify, dir: dir, manifest: manifest}
	v.checkFiles()
	names := make([]string, 0, len(v.checks))
	for _, check := range v.checks {
		names = append(names, check.name)
	}
	return names
}

// discloseSumsRequirePassed fails the test unless the named check ran and passed.
func discloseSumsRequirePassed(t *testing.T, checks map[string]discloseCheck, name string) {
	t.Helper()
	check, ran := checks[name]
	if !ran {
		t.Fatalf("checkFiles recorded no %q check at all", name)
	}
	if !check.passed {
		t.Fatalf("the %q check failed on a package that is correct: %s", name, check.detail)
	}
}

// discloseSumsRequireFailed fails the test unless the named check ran, failed,
// and said why in terms the caller recognises.
func discloseSumsRequireFailed(t *testing.T, checks map[string]discloseCheck, name string, want ...string) {
	t.Helper()
	check, ran := checks[name]
	if !ran {
		t.Fatalf("checkFiles recorded no %q check at all", name)
	}
	if check.passed {
		t.Fatalf("the %q check passed; it reported: %s", name, check.detail)
	}
	for _, phrase := range want {
		if !strings.Contains(check.detail, phrase) {
			t.Fatalf("the %q check does not mention %q, so a recipient cannot act on it: %s",
				name, phrase, check.detail)
		}
	}
}

// The false-refusal guard, and the test that separates this fix from the obvious
// wrong version of it. A correct package has five checksum lines for four
// manifest entries, and must pass.
func TestAnHonestDisclosurePackagePassesBothFileChecks(t *testing.T) {
	dir, manifest, lines := discloseSumsPackage(t)
	if len(lines) != 5 {
		t.Fatalf("the fixture wrote %d checksum lines, want 5: four artifacts and the manifest", len(lines))
	}

	checks := discloseSumsChecks(t, dir, manifest)
	discloseSumsRequirePassed(t, checks, "files")
	discloseSumsRequirePassed(t, checks, "package_contents")
}

// Consequence 1. A checksum line for a file the manifest does not list was
// skipped because it was not listed -- the guard reading as an exemption.
func TestAChecksumLineTheManifestDoesNotListIsReported(t *testing.T) {
	dir, manifest, lines := discloseSumsPackage(t)
	body := []byte("a file somebody added to the package")
	if err := os.WriteFile(filepath.Join(dir, "extra.txt"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	discloseSumsWrite(t, dir, append(lines, discloseSumsDigest(body)+"  extra.txt"))

	checks := discloseSumsChecks(t, dir, manifest)
	discloseSumsRequireFailed(t, checks, "files", "extra.txt", "does not list")
	// And the directory, where the same file is the same finding seen from the
	// other side. Here the wording is the assertion. SHA256SUMS does name
	// extra.txt, so a package_contents detail reporting what "neither the
	// manifest nor SHA256SUMS names" would contradict the files detail directly
	// above it -- in one result, about one file, in opposite directions. What
	// disqualifies extra.txt is that the MANIFEST does not name it, and nothing
	// held the detail to saying so until this line: the test asserted on files
	// alone, which is how the contradictory sentence came to be written.
	discloseSumsRequireFailed(t, checks, "package_contents",
		"extra.txt", "nor a file the manifest names", "vouches for them")
}

// Consequence 2. disclosure.json cannot be in its own file list, so the manifest
// never stood behind its own checksum line and nothing compared it. The line is
// now compared against the manifest on disk, which is the stronger check.
func TestTheManifestsOwnChecksumLineIsComparedAgainstTheManifest(t *testing.T) {
	dir, manifest, lines := discloseSumsPackage(t)
	rewritten := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasSuffix(line, "  "+discloseManifestName) {
			line = strings.Repeat("0", 64) + "  " + discloseManifestName
		}
		rewritten = append(rewritten, line)
	}
	discloseSumsWrite(t, dir, rewritten)

	checks := discloseSumsChecks(t, dir, manifest)
	discloseSumsRequireFailed(t, checks, "files", discloseManifestName, strings.Repeat("0", 64))
}

// Consequence 4. Only the checksum file's lines were walked, so a manifest entry
// with no line at all was never missed. The check is one-way no longer.
func TestAManifestFileWithNoChecksumLineIsReported(t *testing.T) {
	dir, manifest, lines := discloseSumsPackage(t)
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if !strings.HasSuffix(line, "  "+discloseReportName) {
			kept = append(kept, line)
		}
	}
	if len(kept) != len(lines)-1 {
		t.Fatalf("the fixture dropped %d lines, want 1", len(lines)-len(kept))
	}
	discloseSumsWrite(t, dir, kept)

	checks := discloseSumsChecks(t, dir, manifest)
	discloseSumsRequireFailed(t, checks, "files", discloseReportName, "no line in SHA256SUMS")
}

// Consequence 3. Both loops were driven by a list, so nothing ever looked at the
// directory and a file named in neither was invisible to the verification.
func TestAFileNamedInNeitherListIsReported(t *testing.T) {
	dir, manifest, _ := discloseSumsPackage(t)
	if err := os.WriteFile(filepath.Join(dir, "README.txt"), []byte("read me"), 0o600); err != nil {
		t.Fatal(err)
	}

	checks := discloseSumsChecks(t, dir, manifest)
	// The two lists still agree with each other, so that check is untouched:
	// this is a different finding and it is reported as one.
	discloseSumsRequirePassed(t, checks, "files")
	discloseSumsRequireFailed(t, checks, "package_contents", "README.txt", "vouches for them")
}

// The headline, and the shape the old guard made harmless: a checksum file with
// nothing in common with the manifest. The overlap was empty, so no line was
// compared, no problem was recorded, and the verification reported success.
func TestAChecksumFileNamingEntirelyDifferentFilesDoesNotAgreeTrivially(t *testing.T) {
	dir, manifest, _ := discloseSumsPackage(t)
	discloseSumsWrite(t, dir, []string{
		strings.Repeat("a", 64) + "  somebody-elses-record.mrec",
		strings.Repeat("b", 64) + "  somebody-elses-grant.json",
	})

	checks := discloseSumsChecks(t, dir, manifest)
	discloseSumsRequireFailed(t, checks, "files",
		"somebody-elses-record.mrec", "does not list",
		discloseRecordName, "no line in SHA256SUMS")
}

// The comparison that always worked, kept under test so the rewrite cannot lose
// it: a listed file whose bytes changed since the manifest was sealed.
func TestAListedFileThatDoesNotMatchItsManifestDigestStillFails(t *testing.T) {
	dir, manifest, _ := discloseSumsPackage(t)
	if err := os.WriteFile(filepath.Join(dir, discloseRecordName), []byte("different bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	checks := discloseSumsChecks(t, dir, manifest)
	discloseSumsRequireFailed(t, checks, "files", discloseRecordName, "hashes to")
}

// Both findings reach the recipient when both are true. checkFiles used to
// return as soon as it had a problem with the lists, which would have left the
// directory unread and the second finding unreported.
func TestADigestMismatchAndAnUnvouchedFileAreBothReported(t *testing.T) {
	dir, manifest, _ := discloseSumsPackage(t)
	if err := os.WriteFile(filepath.Join(dir, discloseGrantName), []byte("different bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}

	checks := discloseSumsChecks(t, dir, manifest)
	discloseSumsRequireFailed(t, checks, "files", discloseGrantName, "hashes to")
	discloseSumsRequireFailed(t, checks, "package_contents", "notes.txt")
}

// checks_run must not move with the shape of the package. disclose_verify
// reports its result as checks_passed of checks_run, and
// builtin/disclose_bounds_test.go derives the total it expects from a clean run
// -- so a path through checkFiles that records one check fewer than the others
// is invisible there, and it makes two packages' results incomparable: "11 of
// 11" and "11 of 12" are different answers, and a recipient holding two
// disclosures cannot tell from the number which they were handed.
//
// checkFiles records exactly two checks, `files` and then `package_contents`,
// and it has to record both on every path through it. The early return for a
// manifest that lists no files is the one that nearly did not, and it is also
// the case where what the directory actually holds matters most: a manifest
// that vouches for nothing leaves every file in the package unvouched for.
// Reporting eleven checks there and twelve everywhere else would have been a
// count that moved with the failure mode.
//
// The order is pinned with the names, because the two checks are reported as a
// list and a result whose entries move between runs reads as a different
// result to whoever is comparing two of them.
func TestCheckFilesRecordsTheSameTwoChecksOnEveryPath(t *testing.T) {
	const want = "files, package_contents"

	honest, honestManifest, _ := discloseSumsPackage(t)
	empty, _, _ := discloseSumsPackage(t)
	mismatched, mismatchedManifest, _ := discloseSumsPackage(t)
	if err := os.WriteFile(filepath.Join(mismatched, discloseRecordName), []byte("other bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Not merely empty: absent. This is the only shape that reaches the branch
	// where the directory cannot be read at all, and that branch has to record
	// its check too or an unreadable package reports fewer checks than a
	// readable one.
	absent := filepath.Join(t.TempDir(), "no-package-was-ever-written-here")

	for _, shape := range []struct {
		what     string
		dir      string
		manifest map[string]any
	}{
		{"a package that is correct", honest, honestManifest},
		{"a manifest that lists no files", empty, map[string]any{"files": []any{}}},
		{"a manifest with no file list at all", empty, map[string]any{}},
		{"a listed file whose digest does not match", mismatched, mismatchedManifest},
		{"a directory that is not there", absent, honestManifest},
	} {
		got := strings.Join(discloseSumsCheckNames(t, shape.dir, shape.manifest), ", ")
		if got != want {
			t.Errorf("for %s checkFiles recorded %q, want %q", shape.what, got, want)
		}
	}
}
