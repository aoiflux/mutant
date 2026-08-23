package builtin

import (
	"io"
	"os"
	"sync"
)

// Program output (putln/putf) is written through this writer rather than
// straight to the process stdout, so an embedding host can capture it. The
// browser REPL runs the real VM and needs the printed text back as a string to
// hand to JavaScript; the CLI leaves the writer unset and behaves exactly as
// before.
//
// A nil writer means "resolve os.Stdout at call time" rather than a value
// captured at init, so reassigning os.Stdout (as the tests do to capture
// output) keeps working.
//
// The mutex matters because net_serve runs handler VMs on many goroutines at
// once, and each of them may call putln.
var (
	outputMu sync.RWMutex
	output   io.Writer
)

// SetOutput redirects program output and returns a function that restores the
// previous writer. Passing nil restores the os.Stdout default.
func SetOutput(w io.Writer) func() {
	outputMu.Lock()
	previous := output
	output = w
	outputMu.Unlock()

	return func() {
		outputMu.Lock()
		output = previous
		outputMu.Unlock()
	}
}

// Output returns the writer that putln/putf currently print to.
func Output() io.Writer {
	outputMu.RLock()
	w := output
	outputMu.RUnlock()

	if w == nil {
		return os.Stdout
	}
	return w
}
