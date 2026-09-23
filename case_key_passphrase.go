package main

// Where a case-key passphrase comes from.
//
// `security` publishes a hole and `main` fills it, which is the shape
// `security/audit_sink.go` already established and for the same reason: the
// package that knows how to read a secret from a terminal is `credential`, and
// `builtin` must not import it.
//
// "Must not" is three separate facts, not a preference.
//
// The first is that `builtin/gets.go` holds a package-level `bufio.Reader` over
// os.Stdin. Two buffered readers on one descriptor lose bytes between them, so
// a program that called `gets()` and then opened a case key could find its
// passphrase half-eaten by the earlier read.
//
// The second is that `go test` has no terminal. `credential`'s prompt path
// refuses outright when stdin is not one, so a builtin that reached for a
// passphrase during a conformance probe would get an error at best. What
// actually matters is the shape of that error: with no source installed at all,
// `security.RequestPassphrase` fails *before* crypto/rand is read and before
// any file is created. That is what makes "generate a key during `go test`"
// structurally impossible rather than merely improbable, and it is why this
// wiring lives here and is not done in an `init()`.
//
// The third is the import graph. main.go imports `mutant/security` and does not
// import `mutant/builtin`, so a seam published by `builtin` would be one `main`
// could not fill without a new package existing only to be blank-imported.
//
// # A separate request from the bytecode password
//
// This deliberately does not reuse the `credential.Request` that
// `extractPasswordRequest` builds for `.mutx` artifacts. Two reasons, and the
// second is a bug rather than a principle. Reusing it would make the bytecode
// password and the case-key passphrase the same bytes, which conflates
// "who may run this program" with "who may read this evidence". And
// `--password-stdin` is a single `io.ReadAll(os.Stdin)`: whichever consumer
// asked first would drain it, and the second would be told it had been handed
// an empty password.

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"mutant/credential"
	"mutant/security"
)

// caseKeyPassphraseSource reads a passphrase from the terminal.
//
// It remembers, per path, the last passphrase typed or chosen for it, so a
// program that opens one key twice -- or rotates it and reads it back -- asks
// the examiner once. Three rules keep remembering from becoming the wrong
// answer, and each one is here because its absence was a defect:
//
//   - A request to CHOOSE a passphrase is always asked and never answered from
//     memory. The cache used to be keyed by path and by whether confirmation
//     was required, which made "choose one for this path" a question it could
//     answer from a previous choice: `case_key_create` and then
//     `case_key_rotate` in one run answered the rotation's replacement with the
//     create-time passphrase, without asking, and the rotation reported done
//     while leaving the file under the passphrase it already had.
//   - What was chosen becomes what is remembered for that path. Once the
//     builtin that asked has written it, it is the passphrase the file is
//     under, and the one remembered from before is not.
//   - An answer is remembered when it is typed, before anything has checked
//     it, so an answer that failed to open anything is forgotten when the
//     builtin says so through security.ForgetPassphrase. Without that, one
//     typo was the answer to every later request for that path in the run,
//     and the examiner was never asked again.
//
// Every prompt is preceded by a line naming the builtin and what it unlocks.
// The prompt itself only ever says "Password:", and a run that asks for a
// case-key passphrase and a disclosure passphrase must not ask for both in
// words that cannot be told apart -- typing the first where the second was
// meant hands a recipient the key to the whole case.
type caseKeyPassphraseSource struct {
	resolver *credential.Resolver

	mu     sync.Mutex
	cached map[string][]byte
}

func newCaseKeyPassphraseSource() *caseKeyPassphraseSource {
	return &caseKeyPassphraseSource{
		resolver: &credential.Resolver{},
		cached:   map[string][]byte{},
	}
}

// Passphrase implements security.PassphraseSource.
//
// A copy is returned on every call, never the cached slice. The caller zeroes
// what it is given -- every builtin in the case-key family does so in a defer --
// and handing out the cache would leave the second caller with a wiped secret.
func (s *caseKeyPassphraseSource) Passphrase(req security.PassphraseRequest) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := passphraseCacheKey(req.Path)
	if !req.Confirm {
		if held, ok := s.cached[key]; ok {
			return append([]byte(nil), held...), nil
		}
	}

	s.announce(req)
	secret, _, err := s.resolver.Resolve(credential.Request{Confirm: req.Confirm})
	if err != nil {
		return nil, s.explain(req, err)
	}
	if len(secret) == 0 {
		return nil, security.ErrEmptyPassphrase
	}
	if old, ok := s.cached[key]; ok {
		credential.Zero(old)
	}
	s.cached[key] = secret
	return append([]byte(nil), secret...), nil
}

// Forget implements security.PassphraseForgetter: the answer remembered for
// this path did not open what it was asked for, so the next request asks.
func (s *caseKeyPassphraseSource) Forget(req security.PassphraseRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := passphraseCacheKey(req.Path)
	if old, ok := s.cached[key]; ok {
		credential.Zero(old)
		delete(s.cached, key)
	}
}

// passphraseCacheKey is the path as the cache knows it. Two spellings of one
// file are one entry: disclose_verify joins a package directory with the
// grant's name using the platform separator, and a script names the same file
// with forward slashes, and without this the recipient was asked twice for one
// passphrase. The prompt still shows the path as it was given.
func passphraseCacheKey(path string) string {
	return filepath.Clean(path)
}

// announce says which builtin is asking and for what, on the same stream the
// prompt goes to, immediately before it.
func (s *caseKeyPassphraseSource) announce(req security.PassphraseRequest) {
	out := s.resolver.Stderr
	if out == nil {
		out = os.Stderr
	}
	verb := "enter the passphrase for"
	if req.Confirm {
		verb = "choose a passphrase for"
	}
	fmt.Fprintf(out, "%s: %s %s\n", req.Purpose, verb, req.Path)
}

// explain turns credential's failure into one a reader can act on, naming the
// key file and the operation rather than only the mechanism.
func (s *caseKeyPassphraseSource) explain(req security.PassphraseRequest, err error) error {
	return fmt.Errorf("reading the passphrase for %s (%s): %w", req.Path, req.Purpose, err)
}

// installCaseKeyPassphraseSource is called once, from the command line's entry
// point. It is deliberately not an init(): a package that is linked in must not
// acquire the ability to ask for a secret merely by being linked in, and a test
// binary links this package's dependencies without running its command line.
func installCaseKeyPassphraseSource() {
	security.SetPassphraseSource(newCaseKeyPassphraseSource())
}
