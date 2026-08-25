package serve

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"mutant/builtin"
	"mutant/object"
)

// serve_conn/serve_arg are how a net_serve handler learns which connection it is
// running for. Nothing tested them until now, which mattered because the whole
// point is that two handlers running at the same time each see their own
// connection -- the one property a shared lookup can silently get wrong.
//
// These tests drive run() directly with a synthetic connection handle rather
// than over a socket. The handler never touches the connection; it only reports
// what serve_conn/serve_arg told it, which is exactly the mechanism under test,
// and it keeps the test hermetic: no ports, no timing, no cleanup.

// writeHandler writes a handler program to a temp file and prepares it.
func writeHandler(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "handler.mut")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the handler failed: %s", err)
	}
	if errObj := prepare(path); errObj != nil {
		t.Fatalf("preparing the handler failed: %s", errObj.Message)
	}
	return path
}

// The handler reports the two values on one line so a concurrent run's output
// cannot interleave within a single observation.
const reportingHandler = `
let conn, cerr = serve_conn();
let arg, aerr = serve_arg();
putln("[" + to_string(conn) + "|" + to_string(arg) + "]");
`

// syncBuffer collects handler output from several goroutines at once.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// A handler sees the connection handle and the shared arg it was dispatched
// with.
func TestHandlerSeesItsConnectionAndArg(t *testing.T) {
	path := writeHandler(t, reportingHandler)

	var out syncBuffer
	restore := builtin.SetOutput(&out)
	run(path, 4242, &object.String{Value: "shared-context"})
	restore()

	if got := strings.TrimSpace(out.String()); got != "[4242|shared-context]" {
		t.Fatalf("handler reported %q, want \"[4242|shared-context]\"", got)
	}
}

// The same program run outside a handler compiles and runs, and reports no
// context. That is what lets a program serve itself: one file, valid both ways.
func TestServeContextIsNullOutsideAHandler(t *testing.T) {
	var out syncBuffer
	restore := builtin.SetOutput(&out)

	conn := builtin.ServeConn()
	arg := builtin.ServeArg()

	restore()

	for name, result := range map[string]object.Object{"serve_conn": conn, "serve_arg": arg} {
		multi, ok := result.(*object.MultiValue)
		if !ok || len(multi.Values) != 2 {
			t.Fatalf("%s returned %s, want a pair", name, result.Inspect())
		}
		if multi.Values[0].Type() != object.NULL_OBJ {
			t.Fatalf("%s outside a handler returned %s, want null", name, multi.Values[0].Inspect())
		}
		if multi.Values[1].Type() != object.NULL_OBJ {
			t.Fatalf("%s outside a handler reported an error: %s", name, multi.Values[1].Inspect())
		}
	}
}

// The property that matters: handlers running at the same time must not see
// each other's connection. Run with -race for the rest.
func TestConcurrentHandlersSeeTheirOwnContext(t *testing.T) {
	const handlers = 32

	path := writeHandler(t, reportingHandler)

	var out syncBuffer
	restore := builtin.SetOutput(&out)

	var wg sync.WaitGroup
	for i := 0; i < handlers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			run(path, int64(1000+n), &object.Integer{Value: int64(n)})
		}(i)
	}
	wg.Wait()
	restore()

	lines := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines[trimmed] = true
		}
	}

	if len(lines) != handlers {
		t.Fatalf("got %d distinct reports from %d handlers; contexts were shared or lost\n%s",
			len(lines), handlers, out.String())
	}
	for i := 0; i < handlers; i++ {
		// Each handler's connection and arg must have arrived together: a
		// crossed pair is exactly what a shared lookup produces.
		want := "[" + itoa(1000+i) + "|" + itoa(i) + "]"
		if !lines[want] {
			t.Fatalf("no handler reported %s; its context was crossed with another's\n%s", want, out.String())
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// net_spawn dispatches a handler with no connection, and that case has always
// reported 0 rather than null -- a handler can branch on it. Pin it, because "no
// connection" and "connection 0" are easy to collapse into one answer.
func TestSpawnedHandlerReportsConnectionZero(t *testing.T) {
	path := writeHandler(t, reportingHandler)

	var out syncBuffer
	restore := builtin.SetOutput(&out)
	run(path, 0, &object.String{Value: "pump"})
	restore()

	if got := strings.TrimSpace(out.String()); got != "[0|pump]" {
		t.Fatalf("handler reported %q, want \"[0|pump]\"", got)
	}
}

// Work a handler hands to spawn must keep the connection it belongs to. This is
// what the goroutine-keyed lookup could not do: the task runs on a different
// goroutine, so it used to see no context at all.
func TestSpawnedWorkInsideAHandlerKeepsTheContext(t *testing.T) {
	path := writeHandler(t, `
let task, terr = spawn(fn() {
    let conn, cerr = serve_conn();
    let arg, aerr = serve_arg();
    return "[" + to_string(conn) + "|" + to_string(arg) + "]";
});
let reported, werr = task_wait(task);
putln(reported);
`)

	var out syncBuffer
	restore := builtin.SetOutput(&out)
	run(path, 7777, &object.String{Value: "inherited"})
	restore()

	if got := strings.TrimSpace(out.String()); got != "[7777|inherited]" {
		t.Fatalf("the spawned task reported %q, want \"[7777|inherited]\"", got)
	}
}

// The same must hold for pmap's workers, which are built the same way.
func TestPmapWorkersInsideAHandlerKeepTheContext(t *testing.T) {
	path := writeHandler(t, `
let reported = pmap([1, 2, 3], fn(x) {
    let conn, cerr = serve_conn();
    return conn;
});
putln("[" + to_string(reported[0]) + to_string(reported[1]) + to_string(reported[2]) + "]");
`)

	var out syncBuffer
	restore := builtin.SetOutput(&out)
	run(path, 5, &object.Null{})
	restore()

	if got := strings.TrimSpace(out.String()); got != "[555]" {
		t.Fatalf("pmap workers reported %q, want \"[555]\"", got)
	}
}
