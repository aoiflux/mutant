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
	"sync"

	"mutant/credential"
	"mutant/security"
)

// caseKeyPassphraseSource reads a case-key passphrase from the terminal.
//
// Answers are cached per key file for the life of the process, so a program
// that opens the same key twice -- or rotates it and reads it back -- asks the
// examiner once. The cache is keyed by path AND by whether confirmation was
// required, because a create and an open of the same path are different
// questions: one is "choose a passphrase", the other is "prove you know it".
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
	key := fmt.Sprintf("%t\x00%s", req.Confirm, req.Path)

	s.mu.Lock()
	defer s.mu.Unlock()

	if held, ok := s.cached[key]; ok {
		return append([]byte(nil), held...), nil
	}

	secret, _, err := s.resolver.Resolve(credential.Request{Confirm: req.Confirm})
	if err != nil {
		return nil, s.explain(req, err)
	}
	if len(secret) == 0 {
		return nil, security.ErrEmptyPassphrase
	}
	s.cached[key] = secret
	return append([]byte(nil), secret...), nil
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
