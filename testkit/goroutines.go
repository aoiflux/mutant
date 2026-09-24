// Package testkit holds helpers that only tests import. It uses the standard
// library alone, and no non-test file may import it; policy/testkit_guard_test.go
// enforces the second rule, so nothing written for a test ends up in a binary.
package testkit

import (
	"bytes"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// GoroutineSettleTimeout is how long CheckGoroutines waits, after a test ends,
// for the goroutines it started to finish. Long enough for a closed listener's
// accept loop or a cancelled context's workers to notice; short enough that a
// genuine leak fails in seconds rather than at the package timeout.
//
//mutant:limit duration
const GoroutineSettleTimeout = 5 * time.Second

// goroutinePollInterval is how often the count is re-read while settling.
//
//mutant:limit duration
const goroutinePollInterval = 10 * time.Millisecond

// goroutineStackBuffer is the initial buffer for a full stack dump; it doubles
// until the dump fits.
//
//mutant:limit bytes
const goroutineStackBuffer = 64 << 10

// CheckGoroutines records the goroutines alive now and, when the test ends,
// waits up to GoroutineSettleTimeout for every goroutine started since to exit.
// Any that remain fail the test, each named by its stack, so a leak is reported
// by the test that caused it rather than noticed later as a slow machine.
//
// Call it first in a test, before anything the test starts. Tests that use it
// must not run in parallel with other tests in the same binary, whose
// goroutines it would count.
func CheckGoroutines(t testing.TB) {
	t.Helper()
	before := goroutineIDs()
	t.Cleanup(func() {
		deadline := time.Now().Add(GoroutineSettleTimeout)
		for {
			leaked := newGoroutines(before)
			if len(leaked) == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("%d goroutine(s) outlived the test by more than %s:\n\n%s",
					len(leaked), GoroutineSettleTimeout, strings.Join(leaked, "\n\n"))
				return
			}
			time.Sleep(goroutinePollInterval)
		}
	})
}

// goroutineIDs is the set of goroutine header lines alive now.
func goroutineIDs() map[string]bool {
	ids := map[string]bool{}
	for _, g := range goroutineStacks() {
		ids[goroutineID(g)] = true
	}
	return ids
}

// newGoroutines returns the stacks of goroutines not in before, ignoring the
// runtime's own and the testing package's.
func newGoroutines(before map[string]bool) []string {
	var leaked []string
	for _, g := range goroutineStacks() {
		if before[goroutineID(g)] || isBackground(g) {
			continue
		}
		leaked = append(leaked, g)
	}
	sort.Strings(leaked)
	return leaked
}

func goroutineStacks() []string {
	buf := make([]byte, goroutineStackBuffer)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	var stacks []string
	for _, block := range bytes.Split(buf, []byte("\n\n")) {
		if s := strings.TrimSpace(string(block)); strings.HasPrefix(s, "goroutine ") {
			stacks = append(stacks, s)
		}
	}
	return stacks
}

// goroutineID is the "goroutine N" prefix of a stack's header line.
func goroutineID(stack string) string {
	header, _, _ := strings.Cut(stack, "\n")
	id, _, _ := strings.Cut(header, " [")
	return id
}

// isBackground reports goroutines no test owns: the one running the cleanup,
// the testing framework's, and the runtime's.
func isBackground(stack string) bool {
	for _, marker := range []string{
		"testkit.goroutineStacks",
		"testing.(*T).Run",
		"testing.tRunner",
		"testing.runTests",
		"testing.(*M).",
		"runtime.goexit0",
		"signal.signal_recv",
		"runtime.ensureSigM",
	} {
		if strings.Contains(stack, marker) {
			return true
		}
	}
	return false
}
