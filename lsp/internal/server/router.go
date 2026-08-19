package server

import (
	"encoding/json"

	localprotocol "mutant/lsp/internal/protocol"

	"github.com/tliron/glsp"
	lsp "github.com/tliron/glsp/protocol_3_16"
)

// capabilitiesWithInlay augments the protocol-3.16 ServerCapabilities with the
// post-3.16 inlayHintProvider field. Because ServerCapabilities has no custom
// MarshalJSON, its fields and InlayHintProvider all marshal into the same
// "capabilities" JSON object.
type capabilitiesWithInlay struct {
	lsp.ServerCapabilities
	InlayHintProvider any `json:"inlayHintProvider,omitempty"`
}

// initializeResult mirrors lsp.InitializeResult but carries the augmented
// capabilities so we can advertise inlay-hint support.
type initializeResult struct {
	Capabilities capabilitiesWithInlay           `json:"capabilities"`
	ServerInfo   *lsp.InitializeResultServerInfo `json:"serverInfo,omitempty"`
}

// methodRouter dispatches LSP methods that glsp's typed handler cannot route
// (currently only textDocument/inlayHint, which is absent from protocol 3.16)
// and delegates every other method to the standard glsp handler. This is the
// seam that lets us support a post-3.16 request without upgrading glsp.
type methodRouter struct {
	base *lsp.Handler
	srv  *Server
}

func (r *methodRouter) Handle(ctx *glsp.Context) (any, bool, bool, error) {
	if ctx.Method == localprotocol.MethodTextDocumentInlayHint {
		var params localprotocol.InlayHintParams
		if len(ctx.Params) > 0 {
			if err := json.Unmarshal(ctx.Params, &params); err != nil {
				return nil, true, false, err
			}
		}
		return r.srv.inlayHints(&params), true, true, nil
	}
	return r.base.Handle(ctx)
}
