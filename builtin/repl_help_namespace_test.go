package builtin

import (
	"strings"
	"testing"
)

// The REPL is the one surface where the two spellings of a builtin had not been
// reconciled. The compiler folds `hash.blake2` into `hash_blake2`, the editor
// hovers, completes and lints both, and the language reference documents the
// dotted form -- but `help("hash.blake2")` answered "No help found", and typing
// `hash.` offered nothing, because the prefix extractor does not split on a dot
// and nothing in the flat registry begins with `hash.`.
//
// Both read as the dotted spelling not existing, which is the one thing it is
// documented to do.

func TestReplHelpAnswersADottedBuiltin(t *testing.T) {
	for _, pair := range []struct{ dotted, flat string }{
		{"hash.blake2", "hash_blake2"},
		{"str.upper", "str_upper"},
		{"fs.read", "fs_read"},
		{"rand.int", "rand_int"},
	} {
		t.Run(pair.dotted, func(t *testing.T) {
			flat := RenderReplHelp(pair.flat, ReplHelpOptions{})
			if strings.Contains(flat, "No help found") {
				t.Fatalf("the flat spelling stopped answering: %s", flat)
			}

			dotted := RenderReplHelp(pair.dotted, ReplHelpOptions{})
			if strings.Contains(dotted, "No help found") {
				t.Fatalf("help(%q) says no help found; help(%q) answers", pair.dotted, pair.flat)
			}
			if dotted != flat {
				t.Fatalf("the two spellings give different help.\n--- dotted ---\n%s\n--- flat ---\n%s", dotted, flat)
			}
		})
	}
}

// TestReplHelpStillRefusesAnUnknownMember. Folding must not turn every dotted
// string into somebody else's documentation.
func TestReplHelpStillRefusesAnUnknownMember(t *testing.T) {
	for _, topic := range []string{"hash.blake3", "nosuchfamily.member", "a.b.c", "str."} {
		if answer := RenderReplHelp(topic, ReplHelpOptions{}); !strings.Contains(answer, "No help found") {
			t.Errorf("help(%q) answered with %q", topic, answer)
		}
	}
}

// TestReplCompletionOffersAFamilysMembers. Typing `hash.` arrives here whole,
// and used to match nothing.
func TestReplCompletionOffersAFamilysMembers(t *testing.T) {
	candidates := ReplCompletionCandidates("hash.", ReplHelpOptions{})
	if len(candidates) == 0 {
		t.Fatal("typing `hash.` offered no candidates")
	}
	for _, candidate := range candidates {
		if !strings.HasPrefix(candidate, "hash.") {
			t.Errorf("candidate %q is not a member of the hash family", candidate)
		}
	}

	found := false
	for _, candidate := range candidates {
		if candidate == "hash.blake2" {
			found = true
		}
	}
	if !found {
		t.Errorf("hash.blake2 was not offered: %v", candidates)
	}
}

// TestReplCompletionNarrowsOnAPartialMember.
func TestReplCompletionNarrowsOnAPartialMember(t *testing.T) {
	candidates := ReplCompletionCandidates("hash.bla", ReplHelpOptions{})
	if len(candidates) == 0 {
		t.Fatal("typing `hash.bla` offered no candidates")
	}
	for _, candidate := range candidates {
		if !strings.HasPrefix(candidate, "hash.bla") {
			t.Errorf("candidate %q does not match the partial member", candidate)
		}
	}
}

// TestReplCompletionStaysQuietOnANonFamily. A receiver that heads no family is
// a value, and its fields are not this function's business.
func TestReplCompletionStaysQuietOnANonFamily(t *testing.T) {
	for _, prefix := range []string{"nosuchfamily.", "a.b.", "point.x"} {
		for _, candidate := range ReplCompletionCandidates(prefix, ReplHelpOptions{}) {
			if strings.Contains(candidate, ".") {
				t.Errorf("prefix %q was completed with %q", prefix, candidate)
			}
		}
	}
}
