package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// What a cold start costs, which is the whole case for and against caching it
// on disk.
//
// The symbol graph plan deferred "any LSP on-disk persistence". This is the
// measurement that decides it rather than leaving it deferred: over the 123
// .mut files in examples/, a full scan -- read, parse, analyse, index, and file
// every module's facts -- takes 36-44ms on a developer machine, and
// initialized() already runs it on a background goroutine so it blocks nothing.
//
// A cache would save that once per editor session, and would cost three things
// worth more than 40ms:
//
//   - an invalidation story. A file edited while the server was not running has
//     to be noticed, and a cache that gets it wrong answers cross-file
//     questions from a file that no longer exists. That is the failure class
//     this whole package was written to remove.
//   - somewhere to put it. The platform cache directory is reached through the
//     environment -- LOCALAPPDATA, XDG_CACHE_HOME -- and Mutant takes no
//     configuration from environment variables (docs/CONFIGURATION_POLICY.md,
//     enforced by policy/env_guard_test.go). The remaining option is a
//     directory inside the user's project, for a 40ms saving.
//   - a second thing that can be stale. sema.DeclID is explicitly not
//     persistable, so a cache can hold ModuleFacts and nothing else, which
//     means the graphs are rebuilt anyway.
//
// Keep the benchmark rather than the conclusion: if this number ever grows into
// something a person notices, the trade changes and it should be revisited with
// the new number in hand.
func BenchmarkWorkspaceScan(b *testing.B) {
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "examples"))
	if err != nil {
		b.Fatal(err)
	}
	if _, err := os.Stat(root); err != nil {
		b.Skipf("examples tree not readable here: %v", err)
	}

	files := 0
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(path, ".mut") {
			files++
		}
		return nil
	})
	b.Logf("scanning %d .mut files", files)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := New(false)
		s.setRoots([]string{root})
		s.scanWorkspace()
	}
}
