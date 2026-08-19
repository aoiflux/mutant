package server

import (
	"encoding/json"
	"strings"
	"testing"

	localprotocol "mutant/lsp/internal/protocol"

	"github.com/tliron/glsp"
	lsp "github.com/tliron/glsp/protocol_3_16"
)

func TestMethodRouterDispatchesInlayHint(t *testing.T) {
	s := New(false)
	initializeServer(t, s)
	uri := "file:///inlay.mut"
	openMutantDoc(t, s, uri, "let add = fn(a, b) { return a + b; };\nadd(1, 2);\n")

	router := &methodRouter{base: s.handler, srv: s}
	result, validMethod, validParams, err := router.Handle(&glsp.Context{
		Method: localprotocol.MethodTextDocumentInlayHint,
		Params: mustJSON(t, localprotocol.InlayHintParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: lsp.DocumentUri(uri)},
			Range:        lsp.Range{Start: lsp.Position{Line: 0, Character: 0}, End: lsp.Position{Line: 100, Character: 0}},
		}),
	})
	if err != nil {
		t.Fatalf("router inlayHint error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("validity flags method:%t params:%t", validMethod, validParams)
	}
	hints, ok := result.([]localprotocol.InlayHint)
	if !ok {
		t.Fatalf("result type = %T, want []InlayHint", result)
	}
	if len(hints) == 0 {
		t.Fatal("expected inlay hints for add(1, 2)")
	}
}

func TestMethodRouterDelegatesUnknownMethods(t *testing.T) {
	s := New(false)
	router := &methodRouter{base: s.handler, srv: s}
	// A known glsp method must still be dispatched through the base handler.
	_, validMethod, _, err := router.Handle(&glsp.Context{
		Method: string(lsp.MethodInitialize),
		Params: mustJSON(t, lsp.InitializeParams{}),
	})
	if err != nil {
		t.Fatalf("delegated initialize error: %v", err)
	}
	if !validMethod {
		t.Fatal("initialize should be a valid delegated method")
	}
}

func TestInitializeResultSerializesInlayHintProvider(t *testing.T) {
	s := New(false)
	resultAny, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodInitialize),
		Params: mustJSON(t, lsp.InitializeParams{}),
	})
	if err != nil {
		t.Fatalf("initialize error: %v", err)
	}
	raw, err := json.Marshal(resultAny)
	if err != nil {
		t.Fatalf("marshal initialize result: %v", err)
	}
	if !strings.Contains(string(raw), "\"inlayHintProvider\":true") {
		t.Fatalf("serialized capabilities missing inlayHintProvider: %s", raw)
	}
	// Sanity: an existing capability must still serialize alongside it.
	if !strings.Contains(string(raw), "\"foldingRangeProvider\":true") {
		t.Fatalf("serialized capabilities missing foldingRangeProvider: %s", raw)
	}
}
