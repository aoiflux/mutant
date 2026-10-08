package server

import (
	"path/filepath"

	"github.com/tliron/glsp"
	lsp "github.com/tliron/glsp/protocol_3_16"
)

// documentLinks turns string literals that name an existing file into
// clickable links.
//
// "Exists" can only be answered by asking the filesystem, and this handler
// runs on the single goroutine that reads the client's messages, so every
// answer is time the rest of the editor spends waiting. That is what makes the
// shape of the question matter rather than only its result: a literal is first
// decided against a root the operator chose, with no syscall at all, and only
// then looked up -- inside that root, through os.Root, which cannot be talked
// out of it by a device name, a ".." or a symbolic link. See link_path.go.
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
	roots := s.linkRoots(docDir)

	opener := &rootOpener{}
	defer opener.closeAll()

	// The budget counts lookups, not literals: a document repeating one name a
	// thousand times asks once. Spending it is not an error and is not
	// reported -- the links already found are still correct, and a document
	// naming more than a thousand distinct existing files has no reader who
	// would notice the rest.
	asked := map[string]string{}
	var links []lsp.DocumentLink
	for _, ref := range snapshot.StringLiteralRefs() {
		candidate, ok := linkCandidate(docDir, roots, ref.Value)
		if !ok {
			continue
		}
		resolved, seen := asked[ref.Value]
		if !seen {
			if len(asked) >= documentLinkStatBudget {
				break
			}
			resolved, _ = opener.resolveLinkTarget(candidate)
			asked[ref.Value] = resolved
		}
		if resolved == "" {
			continue
		}
		target := pathToURI(resolved)
		links = append(links, lsp.DocumentLink{Range: ref.Range, Target: &target})
	}
	return links, nil
}
