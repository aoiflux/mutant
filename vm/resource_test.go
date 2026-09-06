package vm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// with_resource makes one promise -- the closer runs -- and the tests below are
// the four ways a program can leave the body: it returns a value, it returns an
// error, the call itself is malformed, and the open never succeeded. A channel
// stands in for the twenty handle families because it is the one resource whose
// closure a program can observe from inside the language: sending on a closed
// channel is an error, so "was it closed?" is a question the test can ask
// rather than assume.

func TestWithResourceClosesAfterTheBodyReturns(t *testing.T) {
	// The body hands the handle back out, so the test can ask the runtime
	// whether the closer ran -- rather than trusting that it did.
	result := evalTail(t, `
let handle, err = with_resource(chan_new(1), "chan_close", fn(c) { return c; });
let sent, send_err = chan_send(handle, 1, 0);
send_err.message
`)

	message, ok := result.(*object.String)
	if !ok {
		t.Fatalf("gave %T (%+v), want the send's error message", result, result)
	}
	if !strings.Contains(message.Value, "closed") {
		t.Errorf("sending after with_resource said %q; the channel was left open", message.Value)
	}
}

func TestWithResourceClosesWhenTheBodyReturnsAnError(t *testing.T) {
	// A closer function rather than a name, so the fact that it ran is
	// observable even though the handle never leaves the call.
	result := evalTail(t, `
let ran = false;
let value, err = with_resource(chan_new(1),
    fn(c) { let ok, e = chan_close(c); return ok; },
    fn(c) { return error("body gave up", "test"); });
err.message
`)

	message, ok := result.(*object.String)
	if !ok {
		t.Fatalf("gave %T (%+v), want the body's error message", result, result)
	}
	if message.Value != "body gave up" {
		t.Errorf("err.message = %q, want the body's own error", message.Value)
	}
}

// A malformed call is diagnosed after its arguments have been evaluated, so the
// resource is already open by the time the mistake is found. Reporting the
// mistake and leaking the handle would be the one failure mode this builtin
// exists to prevent.
func TestWithResourceClosesEvenWhenTheCallIsMalformed(t *testing.T) {
	// The handle is opened outside the call so the test can still reach it
	// afterwards. Passing it bare also exercises the other shape with_resource
	// accepts for its first argument: a handle rather than a (handle, err) pair.
	result := evalTail(t, `
let c, open_err = chan_new(1);
let value, err = with_resource(c, "chan_close", fn(h, extra) { return 1; });
let sent, send_err = chan_send(c, 1, 0);
[err.message, send_err.message]
`)

	reported, ok := result.(*object.Array)
	if !ok || len(reported.Elements) != 2 {
		t.Fatalf("gave %T (%+v), want the two messages", result, result)
	}
	complaint := reported.Elements[0].(*object.String).Value
	if !strings.Contains(complaint, "1 parameter") {
		t.Errorf("err = %q, want the body's parameter count named", complaint)
	}
	if closedMessage := reported.Elements[1].(*object.String).Value; !strings.Contains(closedMessage, "closed") {
		t.Errorf("sending afterwards said %q; the malformed call leaked the handle", closedMessage)
	}
}

// A body that dies rather than returning is the case only the VM can make: its
// fatal errors are Go errors, so CallClosureSync hands one back instead of
// unwinding, and the frame and stack pointers are already restored by the time
// hoWithResource sees it. That is what leaves a VM in one piece to close on.
func TestWithResourceClosesWhenTheBodyDies(t *testing.T) {
	// The run does not survive, so the closer cannot report through a value.
	// It writes a file instead, which outlives the VM -- the only witness a
	// dead run can leave.
	witness := filepath.Join(t.TempDir(), "closed")
	src := fmt.Sprintf(`
let value, err = with_resource(chan_new(1),
    fn(h) { let ok, e = fs_write(%q, "closed"); return chan_close(h); },
    fn(h) { let g = fn(a) { return a; }; return g(1, 2); });
`, filepath.ToSlash(witness))

	if _, err := runSealed(t, compilePositioned(t, src)); err == nil {
		t.Fatal("the body called a function with the wrong arity and the run survived it")
	}
	if _, err := os.Stat(witness); err != nil {
		t.Errorf("the closer never ran: %v", err)
	}
}

// When the body and the close both fail, neither may be lost. The body's error
// is the one the program asked about, so it stays the error; the close failure
// is a fact about it, which is what related is for -- and its first production
// use.
func TestWithResourceKeepsBothFailures(t *testing.T) {
	result := evalTail(t, `
let value, err = with_resource(chan_new(1),
    fn(c) { let ok, e = chan_close(c); return error("close failed", "test"); },
    fn(c) { return error("body gave up", "test"); });
[err.message, err.related["close_error"].message]
`)

	reported, ok := result.(*object.Array)
	if !ok || len(reported.Elements) != 2 {
		t.Fatalf("gave %T (%+v), want both messages", result, result)
	}
	if body := reported.Elements[0].(*object.String).Value; body != "body gave up" {
		t.Errorf("err.message = %q, want the body's error to be the one returned", body)
	}
	if closed := reported.Elements[1].(*object.String).Value; closed != "close failed" {
		t.Errorf("related[close_error] = %q, want the close's own error", closed)
	}
}

// Wrapping an existing call must not change what the program sees when the open
// is what failed. If it did, with_resource could not be added to working code
// without re-reading its error handling.
func TestWithResourceIsTransparentToAFailedOpen(t *testing.T) {
	result := evalTail(t, `
let direct, direct_err = ntfs_open("/no/such/image.dd");
let wrapped, wrapped_err = with_resource(ntfs_open("/no/such/image.dd"), "ntfs_close", fn(h) { return 1; });
direct_err == wrapped_err
`)

	same, ok := result.(*object.Boolean)
	if !ok {
		t.Fatalf("gave %T (%+v), want a boolean", result, result)
	}
	if !same.Value {
		t.Error("the wrapped open reported a different error than the bare one")
	}
}

// The standard library returns (value, err), and a body that ends in such a
// call should not force its caller to take a MULTI_VALUE apart by hand.
func TestWithResourcePassesThroughThePairConvention(t *testing.T) {
	result := evalTail(t, `
let sent, err = with_resource(chan_new(1), "chan_close", fn(c) { return chan_send(c, 7, 0); });
sent
`)

	sent, ok := result.(*object.Boolean)
	if !ok {
		t.Fatalf("gave %T (%+v); the body's pair was not unwrapped", result, result)
	}
	if !sent.Value {
		t.Error("the send reported false through with_resource")
	}
}

// A closer that names nothing is refused before anything runs. There is no
// handle to reclaim in that case -- nothing knows how to close it -- so the
// message is all the builtin can offer, and it names the spelling.
func TestWithResourceRefusesACloserThatNamesNothing(t *testing.T) {
	result := evalTail(t, `
let value, err = with_resource(chan_new(1), "chan_clos", fn(c) { return 1; });
err.message
`)

	message, ok := result.(*object.String)
	if !ok {
		t.Fatalf("gave %T (%+v), want an error message", result, result)
	}
	if !strings.Contains(message.Value, "chan_clos") {
		t.Errorf("err = %q; the misspelling is not named", message.Value)
	}
}

// An executor-native builtin drives a user function and closes nothing. Naming
// one would ask the VM to re-enter itself from a cleanup path, so it is refused
// by name rather than attempted.
func TestWithResourceRefusesAnExecutorNativeCloser(t *testing.T) {
	result := evalTail(t, `
let value, err = with_resource(chan_new(1), "each", fn(c) { return 1; });
err.message
`)

	message, ok := result.(*object.String)
	if !ok {
		t.Fatalf("gave %T (%+v), want an error message", result, result)
	}
	if !strings.Contains(message.Value, "cannot close") {
		t.Errorf("err = %q, want the refusal to say why", message.Value)
	}
}
