package workspace

import lsp "github.com/tliron/glsp/protocol_3_16"

type Document struct {
	URI     lsp.DocumentUri
	Version lsp.UInteger
	Text    string
}
