package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"mutant/credential"
	"mutant/security"
)

// scriptedSource is the real source over a terminal that types the given
// answers in order, and a record of what was printed and how often it asked.
func scriptedSource(t *testing.T, answers ...string) (*caseKeyPassphraseSource, *bytes.Buffer, *int) {
	t.Helper()
	var stderr bytes.Buffer
	asked := 0
	source := newCaseKeyPassphraseSource()
	source.resolver = &credential.Resolver{
		Stderr:     &stderr,
		IsTerminal: func() bool { return true },
		ReadSecret: func() ([]byte, error) {
			if asked >= len(answers) {
				t.Fatalf("the terminal was asked %d times and the script has %d answers", asked+1, len(answers))
			}
			answer := answers[asked]
			asked++
			return []byte(answer), nil
		},
	}
	return source, &stderr, &asked
}

func ask(t *testing.T, s *caseKeyPassphraseSource, purpose, path string, confirm bool) string {
	t.Helper()
	secret, err := s.Passphrase(security.PassphraseRequest{Purpose: purpose, Path: path, Confirm: confirm})
	if err != nil {
		t.Fatalf("%s %s: %v", purpose, path, err)
	}
	return string(secret)
}

// The defect this source used to have: create, then rotate the passphrase, in
// one run. The rotation's "choose a replacement" was answered from the
// create-time choice and the terminal was never asked.
func TestChoosingAPassphraseIsAlwaysAsked(t *testing.T) {
	s, _, asked := scriptedSource(t,
		"first", "first", // case_key_create chooses, confirmed
		"second", "second") // case_key_rotate chooses the replacement, confirmed

	if got := ask(t, s, "case_key_create", "case.mkey", true); got != "first" {
		t.Fatalf("create chose %q", got)
	}
	// The current passphrase is a question of knowledge, and the create just
	// answered it.
	if got := ask(t, s, "case_key_rotate", "case.mkey", false); got != "first" {
		t.Fatalf("rotate's current passphrase was %q, want the one just chosen", got)
	}
	if *asked != 2 {
		t.Fatalf("asking for a passphrase just chosen went to the terminal: %d prompts", *asked)
	}
	if got := ask(t, s, "case_key_rotate", "case.mkey", true); got != "second" {
		t.Fatalf("the replacement was %q without being asked; the rotation would have changed nothing", got)
	}
	if *asked != 4 {
		t.Fatalf("choosing a replacement read %d answers from the terminal, want 4", *asked)
	}
	// And the replacement is now what this path is under.
	if got := ask(t, s, "case_key_open", "case.mkey", false); got != "second" {
		t.Fatalf("after the rotation the source answers %q for the file", got)
	}
}

// One file, spelled two ways, is one passphrase. disclose_verify joins the
// package directory and the grant name with the platform separator; the
// script that opens the same grant afterwards names it with forward slashes.
func TestTwoSpellingsOfOnePathAreAskedOnce(t *testing.T) {
	s, _, asked := scriptedSource(t, "grant secret")

	joined := filepath.Join("pkg", "grant.json")
	if got := ask(t, s, "disclose_verify", joined, false); got != "grant secret" {
		t.Fatalf("verify was answered %q", got)
	}
	for _, spelling := range []string{"pkg/grant.json", "pkg/./grant.json", "pkg//grant.json"} {
		if got := ask(t, s, "record_open", spelling, false); got != "grant secret" {
			t.Fatalf("%s was answered %q", spelling, got)
		}
	}
	if *asked != 1 {
		t.Fatalf("one file under four spellings went to the terminal %d times", *asked)
	}

	// Forgetting under one spelling forgets the file.
	s.Forget(security.PassphraseRequest{Purpose: "record_open", Path: "pkg/grant.json"})
	if _, ok := s.cached[passphraseCacheKey(joined)]; ok {
		t.Fatal("a passphrase forgotten under one spelling is still remembered under another")
	}
}

// The other defect: an answer is remembered when typed, before anything has
// checked it, so a typo answered every later request for that path.
func TestAForgottenAnswerIsAskedAgain(t *testing.T) {
	s, _, asked := scriptedSource(t, "tpyo", "typo")

	if got := ask(t, s, "case_key_open", "case.mkey", false); got != "tpyo" {
		t.Fatalf("got %q", got)
	}
	if got := ask(t, s, "case_key_open", "case.mkey", false); got != "tpyo" || *asked != 1 {
		t.Fatalf("a second open of the same file asked again or answered differently: %q after %d prompts", got, *asked)
	}
	s.Forget(security.PassphraseRequest{Purpose: "case_key_open", Path: "case.mkey"})
	if got := ask(t, s, "case_key_open", "case.mkey", false); got != "typo" || *asked != 2 {
		t.Fatalf("after Forget the source answered %q after %d prompts; it must ask again", got, *asked)
	}
	// Forgetting one path leaves another alone.
	s2, _, asked2 := scriptedSource(t, "a", "b")
	ask(t, s2, "case_key_open", "one.mkey", false)
	ask(t, s2, "case_key_open", "two.mkey", false)
	s2.Forget(security.PassphraseRequest{Path: "one.mkey"})
	if got := ask(t, s2, "case_key_open", "two.mkey", false); got != "b" || *asked2 != 2 {
		t.Fatalf("forgetting one path disturbed another: %q after %d prompts", got, *asked2)
	}
}

// Every prompt says who is asking and for what, because the prompt itself
// only ever says "Password:".
func TestEveryPromptSaysWhatItUnlocks(t *testing.T) {
	s, stderr, _ := scriptedSource(t, "k", "g", "g")
	ask(t, s, "case_key_open", `O:\cases\ir-7\case.mkey`, false)
	ask(t, s, "disclose_to_passphrase", "a grant to counsel for the respondent", true)

	out := stderr.String()
	for _, want := range []string{
		`case_key_open: enter the passphrase for O:\cases\ir-7\case.mkey`,
		"disclose_to_passphrase: choose a passphrase for a grant to counsel for the respondent",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the terminal was not told %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "case_key_open") > strings.Index(out, "Password:") {
		t.Errorf("the heading came after the prompt it explains:\n%s", out)
	}
}

// The caller zeroes what it is handed; that must not wipe what is remembered.
func TestTheRememberedAnswerIsNeverTheCallersSlice(t *testing.T) {
	s, _, asked := scriptedSource(t, "hunter2")
	first, err := s.Passphrase(security.PassphraseRequest{Purpose: "case_key_open", Path: "k"})
	if err != nil {
		t.Fatal(err)
	}
	security.SecureZero(first)
	if got := ask(t, s, "case_key_open", "k", false); got != "hunter2" || *asked != 1 {
		t.Fatalf("zeroing the caller's copy reached the cache: %q after %d prompts", got, *asked)
	}
}

// security.ForgetPassphrase reaches this source through the seam, which is the
// path every builtin takes.
func TestForgetPassphraseReachesTheInstalledSource(t *testing.T) {
	s, _, asked := scriptedSource(t, "wrong", "right")
	previous := security.SetPassphraseSource(s)
	t.Cleanup(func() { security.SetPassphraseSource(previous) })

	req := security.PassphraseRequest{Purpose: "case_key_open", Path: "case.mkey"}
	if secret, err := security.RequestPassphrase(req); err != nil || string(secret) != "wrong" {
		t.Fatalf("%q %v", secret, err)
	}
	security.ForgetPassphrase(req)
	if secret, err := security.RequestPassphrase(req); err != nil || string(secret) != "right" || *asked != 2 {
		t.Fatalf("after ForgetPassphrase: %q %v after %d prompts", secret, err, *asked)
	}
}
