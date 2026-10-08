package workspace

import (
	"errors"
	"fmt"
	"sync"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

var ErrStaleDocumentVersion = errors.New("stale document version")

type Store struct {
	mu   sync.RWMutex
	docs map[lsp.DocumentUri]*Document
}

func NewStore() *Store {
	return &Store{docs: make(map[lsp.DocumentUri]*Document)}
}

func (s *Store) Open(uri lsp.DocumentUri, version lsp.UInteger, text string) *Document {
	s.mu.Lock()
	defer s.mu.Unlock()

	doc := &Document{URI: uri, Version: version, Text: text}
	s.docs[uri] = doc
	return cloneDocument(doc)
}

func (s *Store) Snapshot(uri lsp.DocumentUri) (*Document, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	doc, ok := s.docs[uri]
	if !ok {
		return nil, false
	}
	return cloneDocument(doc), true
}

// URIs returns the URI of every open document, exactly as the client spelled
// it. Order is not defined.
//
// It exists so that a caller holding a filesystem path can ask whether any open
// document is that file, which a lookup by URI cannot answer: the same file has
// more than one valid URI spelling, and clients differ on which they send. The
// alternative was a second map here keyed by canonical path, which would have
// put the same fact in two places and required this package to know how paths
// are canonicalised -- a rule that belongs to the server.
func (s *Store) URIs() []lsp.DocumentUri {
	s.mu.RLock()
	defer s.mu.RUnlock()

	uris := make([]lsp.DocumentUri, 0, len(s.docs))
	for uri := range s.docs {
		uris = append(uris, uri)
	}
	return uris
}

func (s *Store) Update(uri lsp.DocumentUri, version lsp.UInteger, changes []any) (*Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	doc, ok := s.docs[uri]
	if !ok {
		return nil, fmt.Errorf("document not open: %s", uri)
	}

	if version <= doc.Version {
		return cloneDocument(doc), ErrStaleDocumentVersion
	}

	text := doc.Text
	for _, raw := range changes {
		var err error
		text, err = applyChange(text, raw)
		if err != nil {
			return nil, err
		}
	}

	doc.Text = text
	doc.Version = version
	return cloneDocument(doc), nil
}

func (s *Store) Close(uri lsp.DocumentUri) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.docs, uri)
}

func applyChange(current string, raw any) (string, error) {
	switch change := raw.(type) {
	case lsp.TextDocumentContentChangeEventWhole:
		return change.Text, nil
	case lsp.TextDocumentContentChangeEvent:
		if change.Range == nil {
			return change.Text, nil
		}
		start, end := change.Range.IndexesIn(current)
		if start < 0 || end < start || end > len(current) {
			return "", fmt.Errorf("invalid change range: %d..%d", start, end)
		}
		return current[:start] + change.Text + current[end:], nil
	default:
		return "", fmt.Errorf("unsupported change payload %T", raw)
	}
}

func cloneDocument(doc *Document) *Document {
	if doc == nil {
		return nil
	}
	clone := *doc
	return &clone
}
