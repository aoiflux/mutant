package evaluator

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// The tree-walker's half of with_resource. The VM's tests cover the same
// promise, and parity/ asserts the two engines answer alike; these exist
// because agreeing is not the same as being right, and because the one thing
// that genuinely differs between the engines -- how a body that gives up
// travels -- can only be exercised from inside each of them.

func evalPairHalves(t *testing.T, src string) (object.Object, *object.Error) {
	t.Helper()

	result := testEval(src)
	pair, ok := result.(*object.MultiValue)
	if !ok || len(pair.Values) != 2 {
		t.Fatalf("%s gave %T (%+v), want a (value, err) pair", src, result, result)
	}
	failure, _ := pair.Values[1].(*object.Error)
	return pair.Values[0], failure
}

func TestWithResourceRunsTheCloserAfterTheBody(t *testing.T) {
	// The body hands the handle back, so the close is observable: sending on a
	// closed channel is an error the program can read.
	value, failure := evalPairHalves(t, `with_resource(chan_new(1), "chan_close", fn(c) { return c; })`)
	if failure != nil {
		t.Fatalf("with_resource reported %v", failure)
	}

	handle, ok := value.(*object.Integer)
	if !ok {
		t.Fatalf("the body's handle came back as %T, want an integer", value)
	}

	result := testEval("chan_send(" + handle.Inspect() + ", 1, 0)")
	pair, ok := result.(*object.MultiValue)
	if !ok || len(pair.Values) != 2 {
		t.Fatalf("chan_send gave %T, want a pair", result)
	}
	sendErr, ok := pair.Values[1].(*object.Error)
	if !ok {
		t.Fatal("sending after with_resource succeeded; the channel was left open")
	}
	if !strings.Contains(sendErr.Message, "closed") {
		t.Errorf("send said %q, want the channel reported closed", sendErr.Message)
	}
}

func TestWithResourceReportsTheBodysError(t *testing.T) {
	value, failure := evalPairHalves(t,
		`with_resource(chan_new(1), "chan_close", fn(c) { return error("body gave up", "test"); })`)

	if failure == nil {
		t.Fatal("the body returned an error and with_resource reported none")
	}
	if failure.Message != "body gave up" {
		t.Errorf("err = %q, want the body's own error", failure.Message)
	}
	if value.Type() != object.NULL_OBJ {
		t.Errorf("value = %s, want null when the body failed", value.Type())
	}
}

// A body that gives up is where the two engines differ. The VM gets a Go error
// back from CallClosureSync; here the fault is an object flowing out of eval,
// and it has to keep flowing -- after the close.
func TestWithResourcePropagatesAFaultAfterClosing(t *testing.T) {
	// The fault ends the program, so the closer cannot report through a value.
	// It writes a file, which is the only witness a run that stopped can leave.
	witness := filepath.Join(t.TempDir(), "closed")
	src := fmt.Sprintf(`
let value = with_resource(chan_new(1),
    fn(c) { let ok, e = fs_write(%q, "closed"); return chan_close(c); },
    fn(c) { return nope(c); });
value
`, filepath.ToSlash(witness))

	result := testEval(src)

	// Eval unwraps the fault at the package boundary, so what comes back here
	// is a plain error rather than the internal signal -- but it is an error
	// and not the (value, err) pair a completed call returns, which is the
	// distinction that matters: the body's failure was not turned into a
	// result.
	failure, ok := result.(*object.Error)
	if !ok {
		t.Fatalf("the body called an unknown identifier and gave %T (%+v); the failure was swallowed", result, result)
	}
	if !strings.Contains(failure.Message, "identifier not found") {
		t.Errorf("gave %q, want the body's own failure", failure.Message)
	}
	if _, err := os.Stat(witness); err != nil {
		t.Errorf("the closer never ran: %v", err)
	}
}

func TestWithResourceIsTransparentToAFailedOpen(t *testing.T) {
	direct := testEval(`let handle, err = ntfs_open("/no/such/image.dd"); err`)
	directErr, ok := direct.(*object.Error)
	if !ok {
		t.Fatalf("ntfs_open on a missing path gave %T, want an error", direct)
	}

	_, wrapped := evalPairHalves(t,
		`with_resource(ntfs_open("/no/such/image.dd"), "ntfs_close", fn(h) { return 1; })`)
	if wrapped == nil {
		t.Fatal("the wrapped open reported no error")
	}
	if !wrapped.Equals(directErr) {
		t.Errorf("wrapped = %q, direct = %q; wrapping changed what the program sees",
			wrapped.Message, directErr.Message)
	}
}

func TestWithResourcePassesThroughThePairConvention(t *testing.T) {
	value, failure := evalPairHalves(t,
		`with_resource(chan_new(1), "chan_close", fn(c) { return chan_send(c, 7, 0); })`)
	if failure != nil {
		t.Fatalf("with_resource reported %v", failure)
	}
	sent, ok := value.(*object.Boolean)
	if !ok {
		t.Fatalf("gave %T (%+v); the body's pair was not unwrapped", value, value)
	}
	if !sent.Value {
		t.Error("the send reported false through with_resource")
	}
}

// A malformed call is a value, not a fault -- the VM answers the same way, and
// the resource is still closed because its arguments had already run.
func TestWithResourceReportsAMalformedCallAsAValue(t *testing.T) {
	_, failure := evalPairHalves(t,
		`with_resource(chan_new(1), "chan_close", fn(c, extra) { return 1; })`)
	if failure == nil {
		t.Fatal("a two-parameter body was accepted")
	}
	if !strings.Contains(failure.Message, "1 parameter") {
		t.Errorf("err = %q, want the parameter count named", failure.Message)
	}
	if failure.Context != "builtin.with_resource" {
		t.Errorf("context = %q, want the builtin's own name", failure.Context)
	}
}
