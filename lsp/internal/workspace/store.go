package workspace

import (
	"fmt"
	"sync"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

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

func (s *Store) Update(uri lsp.DocumentUri, version lsp.UInteger, changes []any) (*Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	doc, ok := s.docs[uri]
	if !ok {
		return nil, fmt.Errorf("document not open: %s", uri)
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
