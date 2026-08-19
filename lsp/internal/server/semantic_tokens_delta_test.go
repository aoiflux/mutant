package server

import (
	"testing"

	"github.com/tliron/glsp"
	lsp "github.com/tliron/glsp/protocol_3_16"
)

func TestSemanticTokenEditsDiff(t *testing.T) {
	tests := []struct {
		name        string
		old, next   []lsp.UInteger
		wantStart   lsp.UInteger
		wantDelete  lsp.UInteger
		wantData    []lsp.UInteger
		wantNoEdits bool // expect a single empty edit list (identical)
	}{
		{name: "identical", old: []lsp.UInteger{1, 2, 3}, next: []lsp.UInteger{1, 2, 3}, wantNoEdits: true},
		{name: "append", old: []lsp.UInteger{1, 2}, next: []lsp.UInteger{1, 2, 3, 4}, wantStart: 2, wantDelete: 0, wantData: []lsp.UInteger{3, 4}},
		{name: "prefix change", old: []lsp.UInteger{9, 2, 3}, next: []lsp.UInteger{1, 2, 3}, wantStart: 0, wantDelete: 1, wantData: []lsp.UInteger{1}},
		{name: "middle replace", old: []lsp.UInteger{1, 9, 9, 4}, next: []lsp.UInteger{1, 5, 4}, wantStart: 1, wantDelete: 2, wantData: []lsp.UInteger{5}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			edits := semanticTokenEdits(tt.old, tt.next)
			if tt.wantNoEdits {
				if len(edits) != 0 {
					t.Fatalf("expected no edits for identical input, got %+v", edits)
				}
				return
			}
			if len(edits) != 1 {
				t.Fatalf("expected exactly 1 edit, got %d (%+v)", len(edits), edits)
			}
			e := edits[0]
			if e.Start != tt.wantStart || e.DeleteCount != tt.wantDelete {
				t.Fatalf("edit start/delete = %d/%d, want %d/%d", e.Start, e.DeleteCount, tt.wantStart, tt.wantDelete)
			}
			if len(e.Data) != len(tt.wantData) {
				t.Fatalf("edit data = %v, want %v", e.Data, tt.wantData)
			}
			for i := range e.Data {
				if e.Data[i] != tt.wantData[i] {
					t.Fatalf("edit data[%d] = %d, want %d", i, e.Data[i], tt.wantData[i])
				}
			}
		})
	}
}

func openMutantDoc(t *testing.T, s *Server, uri, text string) {
	t.Helper()
	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        lsp.DocumentUri(uri),
				LanguageID: "mutant",
				Version:    1,
				Text:       text,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}
}

func TestSemanticTokensFullSetsResultIDAndDeltaFallsBackOnUnknownID(t *testing.T) {
	s := New(false)
	initializeServer(t, s)
	uri := "file:///delta.mut"
	openMutantDoc(t, s, uri, "let a = 1;\nlet b = 2;\n")

	full, err := s.semanticTokensFull(&glsp.Context{}, &lsp.SemanticTokensParams{
		TextDocument: lsp.TextDocumentIdentifier{URI: lsp.DocumentUri(uri)},
	})
	if err != nil {
		t.Fatalf("semanticTokensFull error: %v", err)
	}
	if full.ResultID == nil || *full.ResultID == "" {
		t.Fatalf("full result must carry a ResultID, got %#v", full.ResultID)
	}

	// Unknown previous id -> full fallback (a *SemanticTokens, not a delta).
	res, err := s.semanticTokensFullDelta(&glsp.Context{}, &lsp.SemanticTokensDeltaParams{
		TextDocument:     lsp.TextDocumentIdentifier{URI: lsp.DocumentUri(uri)},
		PreviousResultID: "nonexistent",
	})
	if err != nil {
		t.Fatalf("semanticTokensFullDelta error: %v", err)
	}
	if _, ok := res.(*lsp.SemanticTokens); !ok {
		t.Fatalf("unknown previousResultId should fall back to *SemanticTokens, got %T", res)
	}
}

func TestSemanticTokensDeltaReturnsDeltaForKnownID(t *testing.T) {
	s := New(false)
	initializeServer(t, s)
	uri := "file:///delta2.mut"
	openMutantDoc(t, s, uri, "let a = 1;\nlet b = 2;\n")

	full, err := s.semanticTokensFull(&glsp.Context{}, &lsp.SemanticTokensParams{
		TextDocument: lsp.TextDocumentIdentifier{URI: lsp.DocumentUri(uri)},
	})
	if err != nil {
		t.Fatalf("semanticTokensFull error: %v", err)
	}
	prevID := *full.ResultID

	// No edit between full and delta: expect a *SemanticTokensDelta with no edits.
	res, err := s.semanticTokensFullDelta(&glsp.Context{}, &lsp.SemanticTokensDeltaParams{
		TextDocument:     lsp.TextDocumentIdentifier{URI: lsp.DocumentUri(uri)},
		PreviousResultID: prevID,
	})
	if err != nil {
		t.Fatalf("semanticTokensFullDelta error: %v", err)
	}
	delta, ok := res.(*lsp.SemanticTokensDelta)
	if !ok {
		t.Fatalf("known previousResultId should return *SemanticTokensDelta, got %T", res)
	}
	if len(delta.Edits) != 0 {
		t.Fatalf("unchanged document should produce no edits, got %+v", delta.Edits)
	}
}
