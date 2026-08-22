package server

import (
	"testing"
	"time"

	"github.com/tliron/glsp"
	lsp "github.com/tliron/glsp/protocol_3_16"
)

// TestInitializedDoesNotBlockOnClientCall is a regression test for a deadlock:
// inbound requests are dispatched synchronously on jsonrpc2's single reader
// goroutine, so if the `initialized` handler makes a *blocking* outbound Call
// (client/registerCapability) directly, the reader goroutine stalls forever —
// it ends up waiting for a reply that only it could read. That froze the whole
// server right after startup, so the editor could never reach it.
//
// The earlier tests missed this because they passed a Context whose Call was
// nil, skipping registerFileWatchers entirely. Here Call blocks indefinitely
// (a client that has not yet replied), and the handler must still return
// promptly.
func TestInitializedDoesNotBlockOnClientCall(t *testing.T) {
	s := New(false)

	// glsp gates every method except `initialize` behind IsInitialized(), so we
	// must complete initialize first or the initialized dispatch is rejected
	// before it ever reaches registerFileWatchers.
	if _, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodInitialize),
		Params: mustJSON(t, lsp.InitializeParams{}),
	}); err != nil {
		t.Fatalf("initialize returned error: %v", err)
	}

	blocked := make(chan struct{})
	ctx := &glsp.Context{
		Method: string(lsp.MethodInitialized),
		Params: mustJSON(t, lsp.InitializedParams{}),
		Call: func(_ string, _ any, _ any) {
			close(blocked)
			select {} // never returns: models a client that hasn't replied yet
		},
	}

	done := make(chan struct{})
	go func() {
		_, _, _, _ = s.handler.Handle(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Handler returned without waiting on the outbound Call — correct.
	case <-time.After(2 * time.Second):
		t.Fatal("initialized blocked on the client registerCapability Call (deadlock regression)")
	}

	// The registration Call must still have been dispatched (in the background).
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("registerFileWatchers never issued the client/registerCapability Call")
	}
}
