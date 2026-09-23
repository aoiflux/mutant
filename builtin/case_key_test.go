package builtin

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"mutant/object"
	"mutant/security"
)

// stubPassphrase installs a passphrase source for the duration of one test and
// puts back whatever was there.
//
// Nothing installs one in this package: `main` does, at the command line's
// entry point, which is exactly why a conformance probe calling
// case_key_create with a null argument cannot reach crypto/rand. The tests that
// want the happy path have to say so, one at a time.
func stubPassphrase(t *testing.T, secrets ...string) *int {
	t.Helper()
	calls := 0
	next := 0
	previous := security.SetPassphraseSource(passphraseFunc(func(security.PassphraseRequest) ([]byte, error) {
		calls++
		secret := secrets[len(secrets)-1]
		if next < len(secrets) {
			secret = secrets[next]
			next++
		}
		return []byte(secret), nil
	}))
	t.Cleanup(func() { security.SetPassphraseSource(previous) })
	return &calls
}

type passphraseFunc func(security.PassphraseRequest) ([]byte, error)

func (f passphraseFunc) Passphrase(req security.PassphraseRequest) ([]byte, error) { return f(req) }

// The ordering that keeps `go test` from minting keys.
//
// The four conformance probes call every registered builtin for real, with null
// and wrong-kind arguments. `case_key_create` reads crypto/rand and writes a
// file, so if it validated late it would do both, dozens of times, on every
// test run. This asserts the order rather than trusting it: with no passphrase
// source installed at all -- the state every test binary is in -- a call with a
// bad argument must leave nothing behind.
func TestCaseKeyCreateTouchesNothingBeforeItsArgumentsAreGood(t *testing.T) {
	openTestCase(t, "IR-ORDER", "examiner")
	dir := t.TempDir()
	path := filepath.Join(dir, "case.mkey")

	for _, tc := range []struct {
		name string
		args []object.Object
	}{
		{"no arguments", nil},
		{"three arguments", []object.Object{stringObj(path), makeHashObject(nil), stringObj("x")}},
		{"path is not a string", []object.Object{intObj(7)}},
		{"path is empty", []object.Object{stringObj("   ")}},
		{"options are not a hash", []object.Object{stringObj(path), stringObj("nope")}},
		{"unknown option", []object.Object{stringObj(path), makeHashObject(map[string]object.Object{
			"colour": stringObj("blue")})}},
		{"passphrase as an option", []object.Object{stringObj(path), makeHashObject(map[string]object.Object{
			"passphrase": stringObj("hunter2")})}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, errObj := unwrapPairNoFatal(CaseKeyCreate(tc.args...))
			if errObj == nil {
				t.Fatal("a bad call was accepted")
			}
			if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
				t.Fatalf("a refused call left %d file(s) behind: %v", len(entries), err)
			}
		})
	}
}

// A passphrase is never an argument, and saying so is better than ignoring it.
func TestAPassphraseIsNotAnArgument(t *testing.T) {
	openTestCase(t, "IR-PASS", "examiner")
	path := filepath.Join(t.TempDir(), "case.mkey")

	for _, key := range []string{"passphrase", "password", "secret", "key"} {
		_, errObj := unwrapPairNoFatal(CaseKeyCreate(stringObj(path),
			makeHashObject(map[string]object.Object{key: stringObj("hunter2")})))
		if errObj == nil {
			t.Fatalf("option %q was accepted", key)
		}
		if !strings.Contains(errObj.Message, "asked for at the terminal") {
			t.Fatalf("option %q was refused without saying where a passphrase comes from: %s",
				key, errObj.Message)
		}
	}
}

// With no source installed the refusal has to name the reason, because the
// examiner's next move depends on which it is: a program run from a language
// server or a test has nowhere to ask, and that is not the same as a wrong
// passphrase.
func TestWithNoPassphraseSourceTheRefusalSaysSo(t *testing.T) {
	openTestCase(t, "IR-NOSRC", "examiner")
	previous := security.SetPassphraseSource(nil)
	t.Cleanup(func() { security.SetPassphraseSource(previous) })

	path := filepath.Join(t.TempDir(), "case.mkey")
	_, errObj := unwrapPairNoFatal(CaseKeyCreate(stringObj(path)))
	if errObj == nil {
		t.Fatal("a key was minted with nowhere to ask for a passphrase")
	}
	if !strings.Contains(errObj.Message, "no passphrase source is installed") {
		t.Fatalf("the refusal does not name the reason: %s", errObj.Message)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("the refused call left a key file behind")
	}
}

// The round trip, and the fields a record header will name.
func TestACaseKeyIsMintedOpenedAndDescribed(t *testing.T) {
	openTestCase(t, "IR-2026-0031", "examiner")
	stubPassphrase(t, "correct horse battery staple")
	path := filepath.Join(t.TempDir(), "case.mkey")

	created := mustHash(t, CaseKeyCreate(stringObj(path)))
	fingerprint := keyFieldString(t, created, "fingerprint")
	if !caseKeyHexOK(fingerprint, 32) {
		t.Fatalf("fingerprint %q is not 32 bytes of hex", fingerprint)
	}
	if got := keyFieldString(t, created, "key_id"); got != fingerprint[:16] {
		t.Fatalf("key_id %q is not the first 16 hex of the fingerprint", got)
	}
	if got := keyFieldString(t, created, "case_id"); got != "IR-2026-0031" {
		t.Fatalf("case_id is %q, want the open case's", got)
	}
	if !caseKeyHexOK(keyFieldString(t, created, "case_uid"), 16) {
		t.Fatal("case_uid is not 16 bytes of hex")
	}

	// Minting over an existing key is the unrecoverable mistake.
	_, errObj := unwrapPairNoFatal(CaseKeyCreate(stringObj(path)))
	if errObj == nil {
		t.Fatal("a second key was written over the first")
	}
	if !strings.Contains(errObj.Message, "there is no undo") {
		t.Fatalf("the refusal does not say why it matters: %s", errObj.Message)
	}

	opened := mustHash(t, CaseKeyOpen(stringObj(path)))
	if got := keyFieldString(t, opened, "fingerprint"); got != fingerprint {
		t.Fatalf("the opened key fingerprints %q, the minted one %q", got, fingerprint)
	}

	// Opening twice is refused: two keys on one session would leave one of
	// them with no path to being zeroed.
	if _, errObj := unwrapPairNoFatal(CaseKeyOpen(stringObj(path))); errObj == nil {
		t.Fatal("a second case key was opened over the first")
	}

	// Reading the file claims nothing it cannot back.
	described := mustHash(t, CaseKeyFingerprint(stringObj(path)))
	if authenticated, _ := mustHashValue(t, described, "authenticated").(*object.Boolean); authenticated == nil || authenticated.Value {
		t.Fatal("case_key_fingerprint claims to have authenticated a file it never unlocked")
	}
	if got := keyFieldString(t, described, "case_id"); got != "IR-2026-0031" {
		t.Fatalf("case_key_fingerprint reports case %q", got)
	}
}

// A key belongs to a case, and a key with no case has nothing to protect.
func TestACaseKeyIsRefusedByACaseItDoesNotBelongTo(t *testing.T) {
	openTestCase(t, "IR-FIRST", "examiner")
	stubPassphrase(t, "correct horse battery staple")
	path := filepath.Join(t.TempDir(), "case.mkey")
	mustHash(t, CaseKeyCreate(stringObj(path)))

	// A second case, same process, different id.
	openTestCase(t, "IR-SECOND", "examiner")
	stubPassphrase(t, "correct horse battery staple")

	_, errObj := unwrapPairNoFatal(CaseKeyOpen(stringObj(path)))
	if errObj == nil {
		t.Fatal("a key for another case was opened")
	}
	if !strings.Contains(errObj.Message, "has nothing to protect") {
		t.Fatalf("the refusal does not explain itself: %s", errObj.Message)
	}
}

// Rotation has two meanings and no default, because guessing is the one thing
// a key manager must not do.
func TestRotationRefusesToGuessWhichRotationYouMeant(t *testing.T) {
	openTestCase(t, "IR-ROT", "examiner")
	stubPassphrase(t, "correct horse battery staple")
	path := filepath.Join(t.TempDir(), "case.mkey")
	mustHash(t, CaseKeyCreate(stringObj(path)))

	for _, tc := range []struct {
		name string
		opts object.Object
	}{
		{"no mode", makeHashObject(nil)},
		{"unknown mode", makeHashObject(map[string]object.Object{"mode": stringObj("keys")})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, errObj := unwrapPairNoFatal(CaseKeyRotate(stringObj(path), tc.opts))
			if errObj == nil {
				t.Fatal("a rotation with no mode was accepted")
			}
			if !strings.Contains(errObj.Message, "different operations") {
				t.Fatalf("the refusal does not say why mode is required: %s", errObj.Message)
			}
		})
	}
}

// A record sealed before a case-key rotation still opens: the old generation
// stays in the file and its fingerprint does not move.
func TestRotatingTheCaseKeyKeepsTheGenerationBefore(t *testing.T) {
	openTestCase(t, "IR-GEN", "examiner")
	stubPassphrase(t, "correct horse battery staple")
	path := filepath.Join(t.TempDir(), "case.mkey")

	created := mustHash(t, CaseKeyCreate(stringObj(path)))
	first := keyFieldString(t, created, "fingerprint")

	rotated := mustHash(t, CaseKeyRotate(stringObj(path),
		makeHashObject(map[string]object.Object{"mode": stringObj("case_key")})))
	second := keyFieldString(t, rotated, "fingerprint")
	if second == first {
		t.Fatal("rotating the case key did not change the key")
	}
	if got := keyFieldString(t, rotated, "previous_fingerprint"); got != first {
		t.Fatalf("the rotation names %q as the previous key, not %q", got, first)
	}

	described := mustHash(t, CaseKeyFingerprint(stringObj(path)))
	generations, ok := mustHashValue(t, described, "generations").(*object.Array)
	if !ok || len(generations.Elements) != 2 {
		t.Fatalf("expected two generations after one rotation, got %v", generations)
	}

	// The earlier generation still opens, which is what makes a record sealed
	// under it readable.
	opened := mustHash(t, CaseKeyOpen(stringObj(path),
		makeHashObject(map[string]object.Object{"generation": intObj(1)})))
	if got := keyFieldString(t, opened, "fingerprint"); got != first {
		t.Fatalf("generation 1 opened to %q, want %q", got, first)
	}
}

// Changing the passphrase must change the passphrase, and must leave every
// case key exactly where it was.
func TestRotatingThePassphraseLeavesTheCaseKeyAlone(t *testing.T) {
	openTestCase(t, "IR-PW", "examiner")
	path := filepath.Join(t.TempDir(), "case.mkey")

	stubPassphrase(t, "first passphrase")
	created := mustHash(t, CaseKeyCreate(stringObj(path)))
	before := keyFieldString(t, created, "fingerprint")

	// The rotate asks twice: the current passphrase, then the replacement.
	stubPassphrase(t, "first passphrase", "second passphrase")
	rotated := mustHash(t, CaseKeyRotate(stringObj(path),
		makeHashObject(map[string]object.Object{"mode": stringObj("passphrase")})))
	if got := keyFieldString(t, rotated, "fingerprint"); got != before {
		t.Fatalf("changing the passphrase changed the case key: %q -> %q", before, got)
	}
	if got := keyFieldString(t, rotated, "generation"); got != "1" {
		t.Logf("generation after a passphrase rotation: %s", got)
	}

	// The old passphrase no longer opens it.
	stubPassphrase(t, "first passphrase")
	if _, errObj := unwrapPairNoFatal(CaseKeyOpen(stringObj(path))); errObj == nil {
		t.Fatal("the superseded passphrase still opens the key")
	}

	stubPassphrase(t, "second passphrase")
	opened := mustHash(t, CaseKeyOpen(stringObj(path)))
	if got := keyFieldString(t, opened, "fingerprint"); got != before {
		t.Fatalf("the new passphrase opened a different key: %q, want %q", got, before)
	}
}

// --- classification ---

// A label needs a key, because the tag is keyed to the case.
func TestAClassNeedsAKeyToBeTaggedUnder(t *testing.T) {
	openTestCase(t, "IR-CLASS", "examiner")

	_, errObj := unwrapPairNoFatal(ClassDefine(stringObj("restricted")))
	if errObj == nil {
		t.Fatal("a label was defined with no case key open")
	}
	if !strings.Contains(errObj.Message, "case_key_open") {
		t.Fatalf("the refusal does not say what to call first: %s", errObj.Message)
	}
}

// Two labels that differ only in case or spacing are one label, and the second
// declaration is an error naming the first.
func TestTwoLabelsThatReadTheSameAreOneLabel(t *testing.T) {
	openTestCase(t, "IR-FOLD", "examiner")
	stubPassphrase(t, "correct horse battery staple")
	path := filepath.Join(t.TempDir(), "case.mkey")
	mustHash(t, CaseKeyCreate(stringObj(path)))
	mustHash(t, CaseKeyOpen(stringObj(path)))

	first := mustHash(t, ClassDefine(stringObj("Top Secret")))
	if got := keyFieldString(t, first, "canonical"); got != "top secret" {
		t.Fatalf("canonical form is %q", got)
	}
	tag := keyFieldString(t, first, "tag")
	if !caseKeyHexOK(tag, 32) {
		t.Fatalf("tag %q is not 32 bytes of hex", tag)
	}

	for _, spelling := range []string{"top secret", "  TOP   SECRET  ", "Top secret"} {
		_, errObj := unwrapPairNoFatal(ClassDefine(stringObj(spelling)))
		if errObj == nil {
			t.Fatalf("%q was accepted as a second label", spelling)
		}
		if !strings.Contains(errObj.Message, "already defined") {
			t.Fatalf("%q was refused for the wrong reason: %s", spelling, errObj.Message)
		}
	}

	// A different label gets a different tag.
	second := mustHash(t, ClassDefine(stringObj("restricted")))
	if keyFieldString(t, second, "tag") == tag {
		t.Fatal("two labels share a tag")
	}

	// One letter in two cases, where lowering it produces a form that only a
	// second normalising pass makes equal. Capital J with a combining caron has
	// no precomposed form, so it is already NFC; its lowercase is U+01F0, which
	// does have one. Normalising only before lowering left the canonical form
	// un-normalised, so these were two classes carrying two tags and neither was
	// refused as a duplicate of the other.
	decomposed := mustHash(t, ClassDefine(stringObj("J\u030ceyes-only")))
	if got := keyFieldString(t, decomposed, "canonical"); got != "\u01f0eyes-only" {
		t.Fatalf("the canonical form of a decomposed capital is %+q, want the precomposed lowercase", got)
	}
	if _, errObj := unwrapPairNoFatal(ClassDefine(stringObj("\u01f0eyes-only"))); errObj == nil {
		t.Fatal("the same letter written precomposed was accepted as a second label")
	}
}

// A label that could be mistaken for another in a report is refused outright.
func TestALabelThatCannotBeReadIsRefused(t *testing.T) {
	openTestCase(t, "IR-BAD", "examiner")
	stubPassphrase(t, "correct horse battery staple")
	path := filepath.Join(t.TempDir(), "case.mkey")
	mustHash(t, CaseKeyCreate(stringObj(path)))
	mustHash(t, CaseKeyOpen(stringObj(path)))

	for _, tc := range []struct{ name, label string }{
		{"empty", "   "},
		{"a zero-width joiner", "secret‍ish"},
		{"a control character", "secret\x01"},
		{"longer than a table row", strings.Repeat("x", maxClassLabel+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, errObj := unwrapPairNoFatal(ClassDefine(stringObj(tc.label))); errObj == nil {
				t.Fatalf("%q was accepted as a label", tc.label)
			}
		})
	}
}

// class_list answers with the same keys whether or not there is anything to
// say, so a program reads a field rather than catching an error.
func TestClassListAnswersTheSameWayWithNothingToSay(t *testing.T) {
	resetCustodyForTesting()
	t.Cleanup(resetCustodyForTesting)

	closed := mustHash(t, ClassList())
	for _, key := range []string{"classes", "count", "case_id", "open", "tagged"} {
		mustHashValue(t, closed, key)
	}
	if open, _ := mustHashValue(t, closed, "open").(*object.Boolean); open == nil || open.Value {
		t.Fatal("class_list reports a case open when none is")
	}

	openTestCase(t, "IR-LIST", "examiner")
	untagged := mustHash(t, ClassList())
	if open, _ := mustHashValue(t, untagged, "open").(*object.Boolean); open == nil || !open.Value {
		t.Fatal("class_list does not report the open case")
	}
	if tagged, _ := mustHashValue(t, untagged, "tagged").(*object.Boolean); tagged == nil || tagged.Value {
		t.Fatal("class_list reports a key open when none is")
	}
}

// The manifest always carries the classification block, because an absence
// would leave a reader to infer whether nothing was classified or no key was
// ever opened, and those are different statements.
func TestTheManifestAlwaysSaysWhetherItWasKeyed(t *testing.T) {
	openTestCase(t, "IR-MANIFEST", "examiner")

	manifest := mustHash(t, CaseManifest())
	unkeyed := manifestSection(t, manifest, "classification")
	if keyed, _ := mustHashValue(t, unkeyed, "keyed").(*object.Boolean); keyed == nil || keyed.Value {
		t.Fatal("an unkeyed case reports keyed=true")
	}

	stubPassphrase(t, "correct horse battery staple")
	path := filepath.Join(t.TempDir(), "case.mkey")
	mustHash(t, CaseKeyCreate(stringObj(path)))
	mustHash(t, CaseKeyOpen(stringObj(path)))
	mustHash(t, ClassDefine(stringObj("restricted")))

	manifest = mustHash(t, CaseManifest())
	keyed := manifestSection(t, manifest, "classification")
	if flag, _ := mustHashValue(t, keyed, "keyed").(*object.Boolean); flag == nil || !flag.Value {
		t.Fatal("a keyed case reports keyed=false")
	}
	classes, ok := mustHashValue(t, keyed, "classes").(*object.Array)
	if !ok || len(classes.Elements) != 1 {
		t.Fatalf("the manifest lists %v classes, want 1", classes)
	}
	// The key's PATH must not be in a document meant to be handed over.
	for _, key := range []string{"path", "key_path", "file"} {
		if _, present := hashLookup(keyed, key); present {
			t.Fatalf("the manifest records the key's %q, which is the one thing that must not "+
				"travel with the handover", key)
		}
	}

	// And it still says so once the case is closed. `keyed` is a statement about
	// the investigation and not a probe of what is still in memory: case_close
	// zeroes the key, so a manifest that asked whether the key was live reported
	// a case that had never been keyed -- in the same block that listed the class
	// tagged under that key. Worse, the close renders its own manifest BEFORE it
	// zeroes, so the two documents disagreed about one case.
	closing := mustHash(t, CaseClose())
	for _, after := range []struct {
		name    string
		section *object.Hash
	}{
		{"case_close", manifestSection(t, closing, "classification")},
		{"case_manifest after the close", manifestSection(t, mustHash(t, CaseManifest()), "classification")},
	} {
		flag, _ := mustHashValue(t, after.section, "keyed").(*object.Boolean)
		if flag == nil || !flag.Value {
			t.Errorf("%s reports a closed case as never keyed, while listing the classes "+
				"tagged under its key", after.name)
		}
		if _, present := hashLookup(after.section, "key_fingerprint"); !present {
			t.Errorf("%s drops the key fingerprint, so nothing identifies the key the "+
				"listed tags were derived under", after.name)
		}
	}
}

// A generation number that cannot exist is refused, not narrowed into one that
// can.
//
// The option is read as an int64 and the key file numbers its generations with
// a uint32, and uint32(1 << 32) is 0 -- which is this option's sentinel for
// "whichever generation is current". So asking for a generation far past the
// end quietly opened the live key and reported success, and every number
// congruent to a real generation modulo 2^32 opened that generation.
func TestAGenerationThatCannotExistIsRefusedNotTruncated(t *testing.T) {
	openTestCase(t, "IR-TRUNC", "examiner")
	stubPassphrase(t, "correct horse battery staple")
	path := filepath.Join(t.TempDir(), "case.mkey")
	mustHash(t, CaseKeyCreate(stringObj(path)))

	for _, n := range []int64{1 << 32, (1 << 32) + 1, (1 << 33) + 7} {
		opts := makeHashObject(map[string]object.Object{"generation": &object.Integer{Value: n}})
		value, errObj := unwrapPairNoFatal(CaseKeyOpen(stringObj(path), opts))
		if errObj == nil {
			t.Fatalf("generation %d was accepted and opened %v; it was narrowed to %d",
				n, value, uint32(n))
		}
		if !strings.Contains(errObj.Message, "does not exist") {
			t.Fatalf("generation %d was refused for the wrong reason: %s", n, errObj.Message)
		}
		t.Logf("generation %d refused: %s", n, errObj.Message)
	}
}

// Closing the case is the one place the key dies, and it has to actually do it.
func TestClosingTheCaseZeroesTheKey(t *testing.T) {
	openTestCase(t, "IR-ZERO", "examiner")
	stubPassphrase(t, "correct horse battery staple")
	path := filepath.Join(t.TempDir(), "case.mkey")
	mustHash(t, CaseKeyCreate(stringObj(path)))
	mustHash(t, CaseKeyOpen(stringObj(path)))

	custodyStore.RLock()
	held := custodyStore.session.caseKey
	custodyStore.RUnlock()
	if len(held) == 0 {
		t.Fatal("no case key is held after case_key_open")
	}
	// The slice is retained on purpose: after the close it must read as zeroes
	// through this same backing array.
	copyOfKey := append([]byte(nil), held...)

	mustHash(t, CaseClose())

	for i, b := range held {
		if b != 0 {
			t.Fatalf("byte %d of the case key survived case_close", i)
		}
	}
	allZero := true
	for _, b := range copyOfKey {
		if b != 0 {
			allZero = false
		}
	}
	if allZero {
		t.Fatal("the test's own copy was zero before the close, so this proves nothing")
	}
}

// --- small helpers, kept here so the expectations sit beside the assertions ---

func mustHash(t *testing.T, result object.Object) *object.Hash {
	t.Helper()
	value, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("call failed: %s", errObj.Message)
	}
	hash, ok := value.(*object.Hash)
	if !ok {
		t.Fatalf("call returned %T, want HASH", value)
	}
	return hash
}

func keyFieldString(t *testing.T, hash *object.Hash, key string) string {
	t.Helper()
	value := mustHashValue(t, hash, key)
	switch typed := value.(type) {
	case *object.String:
		return typed.Value
	case *object.Integer:
		return typed.Inspect()
	default:
		t.Fatalf("field %q is %T, want STRING", key, value)
		return ""
	}
}

// forgettingSource answers from a script and records what it was told to
// forget, which is the half of the seam the terminal source depends on.
type forgettingSource struct {
	answers   []string
	next      int
	forgotten []string
}

func (s *forgettingSource) Passphrase(security.PassphraseRequest) ([]byte, error) {
	answer := s.answers[len(s.answers)-1]
	if s.next < len(s.answers) {
		answer = s.answers[s.next]
		s.next++
	}
	return []byte(answer), nil
}

func (s *forgettingSource) Forget(req security.PassphraseRequest) {
	s.forgotten = append(s.forgotten, req.Purpose+" "+req.Path)
}

func installForgetting(t *testing.T, answers ...string) *forgettingSource {
	t.Helper()
	source := &forgettingSource{answers: answers}
	previous := security.SetPassphraseSource(source)
	t.Cleanup(func() { security.SetPassphraseSource(previous) })
	return source
}

// A passphrase that did not open the key is forgotten, so that trying again
// asks again. The terminal source remembers an answer when it is typed; before
// this, one typo at case_key_open answered every later open of that file for
// the rest of the run.
func TestAPassphraseThatDidNotOpenTheKeyIsForgotten(t *testing.T) {
	openTestCase(t, "IR-FORGET", "examiner")
	path := filepath.Join(t.TempDir(), "case.mkey")
	stubPassphrase(t, "the real one")
	mustHash(t, CaseKeyCreate(stringObj(path)))

	source := installForgetting(t, "a typo")
	if _, errObj := unwrapPairNoFatal(CaseKeyOpen(stringObj(path))); errObj == nil {
		t.Fatal("the wrong passphrase opened the key")
	}
	if len(source.forgotten) != 1 || source.forgotten[0] != BuiltinNameCaseKeyOpen+" "+path {
		t.Fatalf("a failed open told the source to forget %v", source.forgotten)
	}

	// A rotation whose current passphrase is wrong forgets it too.
	source = installForgetting(t, "another typo", "a replacement")
	if _, errObj := unwrapPairNoFatal(CaseKeyRotate(stringObj(path),
		makeHashObject(map[string]object.Object{"mode": stringObj("passphrase")}))); errObj == nil {
		t.Fatal("a rotation went through on the wrong current passphrase")
	}
	if len(source.forgotten) != 1 || source.forgotten[0] != BuiltinNameCaseKeyRotate+" "+path {
		t.Fatalf("a failed rotation told the source to forget %v", source.forgotten)
	}

	// A rotation that succeeds forgets nothing: the replacement it chose is
	// now the passphrase the file is under, and that is what the source holds.
	source = installForgetting(t, "the real one", "the new one")
	mustHash(t, CaseKeyRotate(stringObj(path),
		makeHashObject(map[string]object.Object{"mode": stringObj("passphrase")})))
	if len(source.forgotten) != 0 {
		t.Fatalf("a successful rotation told the source to forget %v", source.forgotten)
	}
}

// A rotation that fails after the replacement was chosen -- here, at the write
// -- forgets as well. The source already holds the replacement for this path,
// and the file on disk never got it.
func TestARotationThatDidNotLandIsForgotten(t *testing.T) {
	openTestCase(t, "IR-FORGET-WRITE", "examiner")
	dir := t.TempDir()
	path := filepath.Join(dir, "case.mkey")
	stubPassphrase(t, "the real one")
	mustHash(t, CaseKeyCreate(stringObj(path)))

	// Two ways to make the write fail, because no one way works everywhere.
	// Windows does not honour directory modes, but refuses to rename over a
	// file another handle holds open; POSIX renames over an open file freely,
	// but refuses to create in a directory with no write bit.
	if runtime.GOOS == "windows" {
		held, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = held.Close() })
	} else {
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Skip("cannot make the directory read-only here")
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		probe := filepath.Join(dir, "probe")
		if f, err := os.Create(probe); err == nil {
			f.Close()
			_ = os.Remove(probe)
			t.Skip("directory modes are not enforced here (running as root?)")
		}
	}

	source := installForgetting(t, "the real one", "the new one")
	if _, errObj := unwrapPairNoFatal(CaseKeyRotate(stringObj(path),
		makeHashObject(map[string]object.Object{"mode": stringObj("passphrase")}))); errObj == nil {
		t.Fatal("a rotation reported success into a directory it could not write")
	}
	if len(source.forgotten) != 1 {
		t.Fatalf("a rotation that did not land told the source to forget %v", source.forgotten)
	}
}
