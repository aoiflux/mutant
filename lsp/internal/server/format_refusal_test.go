package server

import (
	"testing"

	"github.com/tliron/glsp"
	lsp "github.com/tliron/glsp/protocol_3_16"
)

// TestFormattingRequestsMakeNoEditsWhenTheFileDoesNotParse is M26-TOOL-014 on
// the editor side.
//
// All three formatting requests used to answer with one edit replacing the
// whole document with its whitespace-normalised self. For a file holding a
// triple-quoted string that meant format-on-save silently shortened string
// data in a file the editor was already reporting as broken. An empty edit
// list is what a language server does here: the diagnostics already say what
// is wrong, and nothing can be formatted until it is fixed.
//
// Everything this test touches is a wire type, so it compiles unchanged
// against the tree that has the defect.
func TestFormattingRequestsMakeNoEditsWhenTheFileDoesNotParse(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	const uri = "file:///format-refusal.mut"
	original := "let banner = \"\"\"\nrow one   \nrow two\n\"\"\";\nlet broken = ;\n"

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        uri,
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	noEdits := func(label string, result any) {
		t.Helper()
		if result == nil {
			return
		}
		edits, ok := result.([]lsp.TextEdit)
		if !ok {
			t.Fatalf("%s result type = %T, want []TextEdit or nil", label, result)
		}
		if len(edits) != 0 {
			t.Errorf("%s returned %d edit(s) for a file that does not parse: %+v", label, len(edits), edits)
		}
	}

	formatAny, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentFormatting),
		Params: mustJSON(t, lsp.DocumentFormattingParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: uri},
		}),
	})
	if err != nil {
		t.Fatalf("formatting returned error: %v", err)
	}
	noEdits("formatting", formatAny)

	rangeAny, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentRangeFormatting),
		Params: mustJSON(t, lsp.DocumentRangeFormattingParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: uri},
			Range: lsp.Range{
				Start: lsp.Position{Line: 0, Character: 0},
				End:   lsp.Position{Line: 4, Character: 0},
			},
		}),
	})
	if err != nil {
		t.Fatalf("rangeFormatting returned error: %v", err)
	}
	noEdits("rangeFormatting", rangeAny)

	onTypeAny, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentOnTypeFormatting),
		Params: mustJSON(t, lsp.DocumentOnTypeFormattingParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: uri},
				Position:     lsp.Position{Line: 4, Character: 14},
			},
			Ch: ";",
		}),
	})
	if err != nil {
		t.Fatalf("onTypeFormatting returned error: %v", err)
	}
	noEdits("onTypeFormatting", onTypeAny)
}
