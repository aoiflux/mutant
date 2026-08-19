package server

import (
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

const (
	// scanMaxFiles bounds a workspace crawl so a huge or pathological tree can
	// never stall startup or exhaust memory.
	scanMaxFiles = 5000
	// scanMaxFileBytes skips oversized files (unlikely to be real Mutant source).
	scanMaxFileBytes = 1 << 20 // 1 MiB
)

// pathToURI converts an absolute filesystem path to a file:// URI. It is the
// canonical form used for disk-indexed documents so go-to-definition into an
// unopened file yields a URI the client can open.
func pathToURI(p string) lsp.DocumentUri {
	slashed := filepath.ToSlash(p)
	if !strings.HasPrefix(slashed, "/") {
		// Windows drive path (O:/project/x.mut) -> /O:/project/x.mut.
		slashed = "/" + slashed
	}
	u := url.URL{Scheme: "file", Path: slashed}
	return lsp.DocumentUri(u.String())
}

// uriToPath converts a file:// URI back to a filesystem path. ok is false for
// non-file URIs.
func uriToPath(uri lsp.DocumentUri) (string, bool) {
	u, err := url.Parse(string(uri))
	if err != nil || u.Scheme != "file" {
		return "", false
	}
	p := u.Path // already percent-decoded
	// Strip the leading slash before a Windows drive: /O:/x -> O:/x.
	if len(p) >= 3 && p[0] == '/' && p[2] == ':' {
		p = p[1:]
	}
	return filepath.FromSlash(p), true
}

// canonicalPath returns a comparison key for a path that is stable across the
// URI-encoding differences between clients (case-insensitive on Windows). It is
// used to detect that a disk-indexed file and a later-opened editor document are
// the same file even when their URIs differ.
func canonicalPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		abs = p
	}
	abs = filepath.Clean(abs)
	if runtime.GOOS == "windows" {
		abs = strings.ToLower(abs)
	}
	return abs
}

// skipScanDir reports whether a directory should be pruned from the crawl.
func skipScanDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor":
		return true
	}
	// Any other dot-directory.
	return strings.HasPrefix(name, ".") && name != "." && name != ".."
}

// collectMutFiles walks roots and returns absolute paths of `*.mut` files,
// bounded by scanMaxFiles. Directories such as .git/node_modules/vendor are
// pruned.
func collectMutFiles(roots []string) []string {
	var files []string
	seen := make(map[string]struct{})

	for _, root := range roots {
		if root == "" {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // ignore unreadable entries, keep walking
			}
			if len(files) >= scanMaxFiles {
				return filepath.SkipAll
			}
			if d.IsDir() {
				if skipScanDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(strings.ToLower(d.Name()), ".mut") {
				return nil
			}
			key := canonicalPath(path)
			if _, dup := seen[key]; dup {
				return nil
			}
			seen[key] = struct{}{}
			files = append(files, path)
			return nil
		})
	}
	return files
}

// indexFileFromDisk reads, analyzes, and indexes a single file under its
// canonical URI, unless an editor already has it open (open snapshots win).
// It records the canonical-path -> URI mapping so a later didOpen can evict the
// stale disk entry. Returns false if the file was skipped.
func (s *Server) indexFileFromDisk(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() > scanMaxFileBytes {
		return false
	}
	uri := pathToURI(path)
	if _, open := s.documents.Snapshot(uri); open {
		return false // an editor copy is authoritative
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	snapshot := s.analyzer.Analyze(string(data))

	s.mu.Lock()
	if s.scanned == nil {
		s.scanned = make(map[string]lsp.DocumentUri)
	}
	s.scanned[canonicalPath(path)] = uri
	s.mu.Unlock()

	s.safeSymbolUpdate(uri, snapshot)
	return true
}

// scanWorkspace indexes every `*.mut` under the configured roots into the symbol
// index (without keeping them as open documents), so cross-file navigation works
// across files the editor has not opened. It runs in the background.
func (s *Server) scanWorkspace() {
	defer func() {
		if recovered := recover(); recovered != nil {
			logRecoveredPanic("workspace.scan", "", recovered)
		}
	}()

	s.mu.RLock()
	roots := append([]string(nil), s.roots...)
	s.mu.RUnlock()
	if len(roots) == 0 {
		return
	}

	for _, path := range collectMutFiles(roots) {
		s.indexFileFromDisk(path)
	}
}

// evictScannedEntryFor removes a stale disk-indexed symbol entry when the editor
// opens the same underlying file under a different URI, preventing duplicate
// (and therefore ambiguous) cross-file symbols.
func (s *Server) evictScannedEntryFor(openedURI lsp.DocumentUri) {
	path, ok := uriToPath(openedURI)
	if !ok {
		return
	}
	key := canonicalPath(path)

	s.mu.Lock()
	staleURI, tracked := s.scanned[key]
	if tracked {
		delete(s.scanned, key)
	}
	s.mu.Unlock()

	if tracked && staleURI != openedURI {
		s.safeSymbolDelete(staleURI)
	}
}
