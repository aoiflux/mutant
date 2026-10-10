package workspace

import lsp "github.com/tliron/glsp/protocol_3_16"

type Document struct {
	URI     lsp.DocumentUri
	Version lsp.UInteger
	Text    string

	// Desynced records that this copy of the document is known not to be the
	// client's. It is set when a change could not be applied, and it is what
	// stops the next change being applied to text that is already wrong.
	//
	// The protocol gives a server no way to ask for a document again: there is
	// no "send it to me once more" request, only the client's own didOpen and
	// whole-document changes. So the only two honest states for a stored
	// document are "this is what the client has" and "this is not", and
	// everything that hands the client an edit built from this text has to be
	// able to tell them apart (M26-LSP-004).
	//
	// Only a whole-document change or a fresh didOpen clears it.
	Desynced bool
}
