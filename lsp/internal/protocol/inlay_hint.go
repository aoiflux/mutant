package protocol

import lsp "github.com/tliron/glsp/protocol_3_16"

// The glsp library we depend on implements LSP 3.16, which predates inlay hints
// (added in 3.17). These are the minimal wire types for textDocument/inlayHint,
// routed manually by the server (see server/router.go) since glsp's typed
// handler cannot dispatch a method it does not know.

// MethodTextDocumentInlayHint is the LSP request method for inlay hints.
const MethodTextDocumentInlayHint = "textDocument/inlayHint"

// Inlay hint kinds (LSP: Type = 1, Parameter = 2).
const (
	InlayHintKindType      lsp.UInteger = 1
	InlayHintKindParameter lsp.UInteger = 2
)

// InlayHintParams is the request payload: hints are requested for a range.
type InlayHintParams struct {
	TextDocument lsp.TextDocumentIdentifier `json:"textDocument"`
	Range        lsp.Range                  `json:"range"`
}

// InlayHint is a single rendered hint. Label is kept as a plain string (the LSP
// permits string | InlayHintLabelPart[]); that is all we emit.
type InlayHint struct {
	Position     lsp.Position  `json:"position"`
	Label        string        `json:"label"`
	Kind         *lsp.UInteger `json:"kind,omitempty"`
	PaddingLeft  *bool         `json:"paddingLeft,omitempty"`
	PaddingRight *bool         `json:"paddingRight,omitempty"`
}
