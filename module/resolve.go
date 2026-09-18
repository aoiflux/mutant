// Package module resolves `import` paths to files and walks the resulting
// graph. It is the single owner of path-to-file logic: nothing else in the
// compiler, the CLI or the tooling decides what a written import path means.
//
// Resolution is deliberately narrow. A path is looked for relative to the
// importing file first, then in each directory named by a `--module-path`
// flag, in the order the flags were given. There is no manifest, no config
// file and no environment variable -- per docs/CONFIGURATION_POLICY.md, where
// a module came from has to be visible in the invocation that built it.
package module

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mutant/sema"
)

// Extension is the suffix every Mutant source file carries. An import path
// must spell it out: `import "pkg/util"` is rejected rather than quietly
// completed, so the text in the file names the file on disk exactly.
const Extension = ".mut"

// Resolver turns an import path as written into the absolute path of a file.
//
// The zero value is usable and resolves relative imports only.
type Resolver struct {
	searchPaths []string
}

// NewResolver returns a Resolver that searches the given directories, in
// order, for any import that does not resolve relative to its importer.
//
// The directories come from repeated `--module-path` flags. Order is the
// order they were passed: the first match wins, so a caller can shadow a
// library by putting its own directory first.
func NewResolver(searchPaths []string) *Resolver {
	cleaned := make([]string, 0, len(searchPaths))
	for _, dir := range searchPaths {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		if abs, err := filepath.Abs(dir); err == nil {
			dir = abs
		}
		cleaned = append(cleaned, filepath.Clean(dir))
	}
	return &Resolver{searchPaths: cleaned}
}

// SearchPaths returns the directories this resolver searches, in order.
func (r *Resolver) SearchPaths() []string {
	if r == nil {
		return nil
	}
	return append([]string(nil), r.searchPaths...)
}

// Resolve returns the absolute path of the file spelling names, as imported
// from a file in importerDir.
//
// The candidate list is returned on failure as part of NotFoundError, because
// "cannot find pkg/util.mut" is not an actionable message -- the reader needs
// to know which directories were looked in to know which one to fix.
func (r *Resolver) Resolve(spelling, importerDir string) (string, error) {
	if err := validateSpelling(spelling); err != nil {
		return "", err
	}

	local := filepath.FromSlash(spelling)

	// An absolute import bypasses the search entirely: there is exactly one
	// file it could mean, and joining it onto a search directory would produce
	// a path that names nothing.
	if filepath.IsAbs(local) {
		candidate := filepath.Clean(local)
		if fileExists(candidate) {
			return candidate, nil
		}
		return "", &NotFoundError{Spelling: spelling, ImporterDir: importerDir, Searched: []string{candidate}}
	}

	searched := make([]string, 0, len(r.searchPaths)+1)

	if importerDir != "" {
		candidate := filepath.Clean(filepath.Join(importerDir, local))
		if fileExists(candidate) {
			return candidate, nil
		}
		searched = append(searched, candidate)
	}

	for _, dir := range r.searchPaths {
		candidate := filepath.Clean(filepath.Join(dir, local))
		if fileExists(candidate) {
			return candidate, nil
		}
		searched = append(searched, candidate)
	}

	return "", &NotFoundError{Spelling: spelling, ImporterDir: importerDir, Searched: searched}
}

// validateSpelling rejects import paths that cannot name a Mutant source file.
func validateSpelling(spelling string) error {
	trimmed := strings.TrimSpace(spelling)
	if trimmed == "" {
		return &InvalidPathError{Spelling: spelling, Reason: "the path is empty"}
	}
	if !strings.HasSuffix(trimmed, Extension) {
		return &InvalidPathError{
			Spelling: spelling,
			Reason:   fmt.Sprintf("an import path must end in %s", Extension),
		}
	}
	if len(trimmed) == len(Extension) {
		return &InvalidPathError{Spelling: spelling, Reason: "the path names no file, only the extension"}
	}
	return nil
}

// canonicalKey returns the identity of a file: the value two spellings of the
// same file must share, so a diamond import compiles it once.
//
// The rule itself lives in sema, which also files every fact it holds under
// this key, and which the language server can import where it cannot import
// this package. Two independently-written copies of the rule that defines
// module identity is how modules come to silently fail to match across
// case-differing paths, so this forwards rather than repeating it.
func canonicalKey(absolutePath string) string {
	return sema.CanonicalKey(absolutePath)
}

// fileExists reports whether path names an existing regular file. A directory
// with the right name is not a module, so it must not satisfy an import and
// stop the search early.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}
