package builtin

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"mutant/object"
)

// secretOptionFamilies are the builtins that handle a case, its key, its
// classes, its records or their disclosure: the ones DISCLOSURE_POLICY section 8
// speaks for when it says an option named for a secret is refused by name.
var secretOptionFamilies = []string{"case_", "class_", "record_", "view_", "disclose_", "evidence_", "role_",
	"redaction_"}

// optionsPosition is the 1-based position of a builtin's options hash, or 0.
func optionsPosition(doc builtinDoc) int {
	for i, p := range doc.params {
		switch strings.TrimSuffix(p.name, "?") {
		case "options", "opts":
			return i + 1
		}
	}
	return 0
}

// M26-DOC3-010. The by-name refusal of a passphrase option was made only by
// case_key_*. record_open, record_seal, view_define and the others answered
// `unknown option "passphrase"`, which reads as a misspelling, and case_open
// and case_evidence did not look at unknown keys at all. Every builtin in these
// families with an options hash now refuses the four names first, before any
// other argument is looked at -- which is why the others here are placeholders.
func TestEveryOptionNamedForASecretIsRefusedByName(t *testing.T) {
	t.Chdir(t.TempDir())
	var names []string
	for name, doc := range builtinDocs {
		for _, prefix := range secretOptionFamilies {
			if strings.HasPrefix(name, prefix) && optionsPosition(doc) > 0 {
				names = append(names, name)
				break
			}
		}
	}
	sort.Strings(names)
	// The metadata scan is the test's reach; if a rename made it find nothing,
	// every assertion below would pass by not running.
	if len(names) < 13 {
		t.Fatalf("found %d builtins with an options hash in these families, want at least 13: %v", len(names), names)
	}

	for _, name := range names {
		position := optionsPosition(builtinDocs[name])
		fn := GetBuiltinByName(name)
		if fn == nil {
			t.Fatalf("%s has metadata and no builtin", name)
		}
		for _, secret := range []string{"passphrase", "password", "secret", "key"} {
			t.Run(name+"/"+secret, func(t *testing.T) {
				resetCustodyForTesting()
				t.Cleanup(resetCustodyForTesting)
				args := make([]object.Object, position)
				for i := range args {
					args[i] = stringObj("placeholder")
				}
				args[position-1] = makeHashObject(map[string]object.Object{secret: stringObj("hunter2")})
				_, errObj := unwrapPairNoFatal(fn.Fn(args...))
				if errObj == nil || !strings.Contains(errObj.Message, "is not an argument") {
					t.Fatalf("an option named %q was not refused by name: %v", secret, errObj)
				}
				if strings.Contains(errObj.Message, "hunter2") {
					t.Fatal("the refusal repeats the secret it refused")
				}
			})
		}
	}
}

// M26-CUS-012. case_open and case_evidence read their hash option with a helper
// that fell back to the default for anything it did not recognise: a string
// instead of a hash, the result's own field name, another spelling, a value that
// is not a string. Each opened or registered with no digest and no error, and
// case_write did the same with its sign option. Each is now refused.
func TestAMalformedCaseOptionIsRefusedNotIgnored(t *testing.T) {
	hash := func(key string, value object.Object) object.Object {
		return makeHashObject(map[string]object.Object{key: value})
	}
	list := &object.Array{Elements: []object.Object{stringObj("sha256")}}
	malformed := []struct {
		name   string
		option object.Object
	}{
		{"a string, not a hash", stringObj("sha256")},
		{"the result's field name", hash("hash_policy", stringObj("sha256"))},
		{"another spelling", hash("Hash", stringObj("sha256"))},
		{"a list, not a string", hash("hash", list)},
	}
	for _, bad := range malformed {
		t.Run("case_open/"+bad.name, func(t *testing.T) {
			resetCustodyForTesting()
			t.Cleanup(resetCustodyForTesting)
			if _, errObj := unwrapPairNoFatal(CaseOpen(stringObj("IR-1"), stringObj("examiner"), bad.option)); errObj == nil {
				t.Fatalf("case_open accepted %s and opened a case", bad.option.Inspect())
			}
		})
		t.Run("case_evidence/"+bad.name, func(t *testing.T) {
			openTestCase(t, "IR-1", "examiner")
			path := filepath.Join(t.TempDir(), "carved.bin")
			if err := os.WriteFile(path, []byte("carved"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, errObj := unwrapPairNoFatal(CaseEvidence(stringObj(path), bad.option)); errObj == nil {
				t.Fatalf("case_evidence accepted %s and registered the file", bad.option.Inspect())
			}
		})
	}
	for _, bad := range []struct {
		name   string
		option object.Object
	}{
		{"another spelling", hash("signed", boolObj(false))},
		{"a string, not a boolean", hash("sign", stringObj("no"))},
	} {
		t.Run("case_write/"+bad.name, func(t *testing.T) {
			openTestCase(t, "IR-1", "examiner")
			path := filepath.Join(t.TempDir(), "manifest.json")
			if _, errObj := unwrapPairNoFatal(CaseWrite(stringObj(path), bad.option)); errObj == nil {
				t.Fatalf("case_write accepted %s and wrote the manifest", bad.option.Inspect())
			}
			if _, err := os.Stat(path); err == nil {
				t.Fatal("the refused case_write left a manifest behind")
			}
		})
	}
}
