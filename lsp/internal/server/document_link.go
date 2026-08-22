package server

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/tliron/glsp"
	lsp "github.com/tliron/glsp/protocol_3_16"
)

// documentLinks turns string literals that name an existing file (absolute, or
// relative to the document's directory) into clickable links. Only real files
// are linked, so arbitrary strings are never underlined.
func (s *Server) documentLinks(_ *glsp.Context, params *lsp.DocumentLinkParams) ([]lsp.DocumentLink, error) {
	snapshot, ok := s.snapshot(params.TextDocument.URI)
	if !ok {
		return nil, nil
	}
	docPath, ok := uriToPath(params.TextDocument.URI)
	if !ok {
		return nil, nil
	}
	docDir := filepath.Dir(docPath)

	var links []lsp.DocumentLink
	for _, ref := range snapshot.StringLiteralRefs() {
		resolved, ok := resolveExistingFile(docDir, ref.Value)
		if !ok {
			continue
		}
		target := pathToURI(resolved)
		links = append(links, lsp.DocumentLink{Range: ref.Range, Target: &target})
	}
	return links, nil
}

// resolveExistingFile resolves value against dir (unless absolute) and returns
// the path only if it names an existing, non-directory file.
func resolveExistingFile(dir, value string) (string, bool) {
	if value == "" || strings.ContainsAny(value, "\n\r\x00") {
		return "", false
	}
	candidate := value
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(dir, candidate)
	}
	info, err := os.Stat(candidate)
	if err != nil || info.IsDir() {
		return "", false
	}
	return candidate, true
}
