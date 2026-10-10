package workspace

import (
	"errors"
	"fmt"
	"sync"

	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

var (
	ErrStaleDocumentVersion = errors.New("stale document version")

	// ErrDocumentDesynced is returned for an incremental change against a
	// document this store knows it does not hold the client's copy of. Applying
	// it would produce text that is neither side's.
	ErrDocumentDesynced = errors.New("document out of step with the client")
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

	// A fresh didOpen carries the whole text, so it is also the resynchronisation
	// a desynced document was waiting for: the new Document starts in step.
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

// Update applies one version's changes to the stored document.
//
// A change that cannot be applied marks the document desynced and leaves its
// text and its version where they were. Advancing the version over text a
// change never reached is what M26-LSP-004 was: didChange is a notification, so
// the error returned here reaches nobody, and the next version's changes were
// then applied to stale text and accepted -- measured, a refused v2 followed by
// a v3 that succeeded left the store holding "let b = 2; putln(b);" while the
// client held "let b = 3; putln(b);", for as long as the file stayed open. The
// next format-on-save then replaced the user's work with the server's copy.
//
// Keeping the old version and refusing what comes next is the honest answer
// rather than a cautious one: there is no request that asks a client to send a
// document again, so a store that cannot apply a change cannot get back in step
// on its own, and the only thing it can do is stop pretending it is.
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
	desynced := doc.Desynced
	for _, raw := range changes {
		if whole, ok := wholeDocumentText(raw); ok {
			// A full copy of the document is the one thing that can put the two
			// sides back in step, and it needs nothing from the text it
			// replaces, so it is accepted even while desynced.
			text, desynced = whole, false
			continue
		}
		if desynced {
			return cloneDocument(doc), ErrDocumentDesynced
		}
		var err error
		text, err = applyChange(text, raw)
		if err != nil {
			doc.Desynced = true
			return cloneDocument(doc), err
		}
	}

	doc.Text = text
	doc.Version = version
	doc.Desynced = desynced
	return cloneDocument(doc), nil
}

func (s *Store) Close(uri lsp.DocumentUri) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.docs, uri)
}

// wholeDocumentText is the text of a change that replaces the document
// entirely, which the protocol spells two ways: the dedicated whole-document
// event, and an ordinary change event carrying no range.
func wholeDocumentText(raw any) (string, bool) {
	switch change := raw.(type) {
	case lsp.TextDocumentContentChangeEventWhole:
		return change.Text, true
	case lsp.TextDocumentContentChangeEvent:
		if change.Range == nil {
			return change.Text, true
		}
	}
	return "", false
}

func applyChange(current string, raw any) (string, error) {
	change, ok := raw.(lsp.TextDocumentContentChangeEvent)
	if !ok {
		return "", fmt.Errorf("unsupported change payload %T", raw)
	}
	if change.Range == nil {
		return change.Text, nil
	}

	// localprotocol and not glsp's own Range.IndexesIn, which answers offset 0
	// for any position past the end of the content: measured against v0.2.2, an
	// insert at (0, 10) in "abc" came back 0..0 and landed at the START of the
	// document, and a range ending at (lineCount, 0) came back 11..0, an end
	// before its own start. EditOffsets clamps the way the protocol says to.
	start, end, ok := localprotocol.EditOffsets(current, *change.Range)
	if !ok {
		return "", fmt.Errorf("unusable change range %d:%d-%d:%d",
			change.Range.Start.Line, change.Range.Start.Character,
			change.Range.End.Line, change.Range.End.Character)
	}
	// EditOffsets cannot return a range outside the content -- that is its
	// contract and its tests -- but this slices a string inside a language
	// server, where a panic does not fail one request, it ends the session and
	// takes the editor's language support with it. A refusal costs one keystroke.
	if start < 0 || end < start || end > len(current) {
		return "", fmt.Errorf("change range out of bounds: %d..%d of %d", start, end, len(current))
	}
	return current[:start] + change.Text + current[end:], nil
}

func cloneDocument(doc *Document) *Document {
	if doc == nil {
		return nil
	}
	clone := *doc
	return &clone
}
