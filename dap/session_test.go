package dap

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// messageTimeout bounds every wait. A handshake that never completes would
// otherwise hang the package's test run with nothing to say about why.
const messageTimeout = 30 * time.Second

// anyMessage is one decoded message of any of the three kinds. The test reads
// the wire rather than the adapter's own types, so a change to a JSON tag shows
// up here as a failure instead of passing silently on both sides.
type anyMessage struct {
	Type       string          `json:"type"`
	Seq        int             `json:"seq"`
	RequestSeq int             `json:"request_seq"`
	Success    bool            `json:"success"`
	Command    string          `json:"command"`
	Message    string          `json:"message"`
	Event      string          `json:"event"`
	Body       json.RawMessage `json:"body"`
}

// client is a debug client speaking to the adapter over a pair of pipes.
//
// Incoming messages are drained by a goroutine into a channel rather than read
// on demand. The adapter publishes events while the client is between requests,
// and a client that only read when it wanted something would block the adapter
// mid-write and deadlock the pair.
type client struct {
	t        *testing.T
	conn     *conn
	incoming chan anyMessage
	pending  []anyMessage
	seq      int
	served   chan error
}

func newClient(t *testing.T, options Options) *client {
	t.Helper()

	serverIn, clientOut := io.Pipe()
	clientIn, serverOut := io.Pipe()

	c := &client{
		t:        t,
		conn:     newConn(clientIn, clientOut),
		incoming: make(chan anyMessage, 256),
		served:   make(chan error, 1),
	}

	go func() { c.served <- Serve(serverIn, serverOut, options) }()

	go func() {
		defer close(c.incoming)
		for {
			payload, err := c.conn.readFrame()
			if err != nil {
				return
			}
			var msg anyMessage
			if err := json.Unmarshal(payload, &msg); err != nil {
				return
			}
			c.incoming <- msg
		}
	}()

	t.Cleanup(func() {
		clientOut.Close()
		clientIn.Close()
	})
	return c
}

// request sends one request and returns its sequence number.
func (c *client) request(command string, arguments any) int {
	c.t.Helper()

	c.seq++
	raw := json.RawMessage(nil)
	if arguments != nil {
		encoded, err := json.Marshal(arguments)
		if err != nil {
			c.t.Fatalf("encoding %s arguments: %v", command, err)
		}
		raw = encoded
	}

	if err := c.conn.send(&request{
		Seq: c.seq, Type: "request", Command: command, Arguments: raw,
	}); err != nil {
		c.t.Fatalf("sending %s: %v", command, err)
	}
	return c.seq
}

// next returns the next message, preferring ones already set aside.
func (c *client) next() anyMessage {
	c.t.Helper()

	if len(c.pending) > 0 {
		msg := c.pending[0]
		c.pending = c.pending[1:]
		return msg
	}

	select {
	case msg, open := <-c.incoming:
		if !open {
			c.t.Fatal("the adapter closed the connection")
		}
		return msg
	case <-time.After(messageTimeout):
		c.t.Fatal("the adapter sent nothing")
		return anyMessage{}
	}
}

// response waits for the answer to one request, setting aside any events that
// arrive first so a later wait can still find them.
func (c *client) response(seq int) anyMessage {
	c.t.Helper()

	var held []anyMessage
	for {
		msg := c.next()
		if msg.Type == "response" && msg.RequestSeq == seq {
			c.pending = append(held, c.pending...)
			return msg
		}
		held = append(held, msg)
	}
}

// call sends a request and returns the response, insisting that it succeeded.
func (c *client) call(command string, arguments any) anyMessage {
	c.t.Helper()

	reply := c.response(c.request(command, arguments))
	if !reply.Success {
		c.t.Fatalf("%s failed: %s", command, reply.Message)
	}
	return reply
}

// event waits for a named event.
func (c *client) event(name string) anyMessage {
	c.t.Helper()

	var held []anyMessage
	for {
		msg := c.next()
		if msg.Type == "event" && msg.Event == name {
			c.pending = append(held, c.pending...)
			return msg
		}
		held = append(held, msg)
	}
}

// body decodes a message body into out.
func (c *client) body(msg anyMessage, out any) {
	c.t.Helper()

	if err := json.Unmarshal(msg.Body, out); err != nil {
		c.t.Fatalf("decoding body %s: %v", msg.Body, err)
	}
}

// write puts a program in a temporary directory and returns its path.
func write(t *testing.T, name, source string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

// start runs the handshake up to the point where breakpoints can be set.
func (c *client) start(program string, stopOnEntry bool) {
	c.t.Helper()

	c.call("initialize", map[string]any{"adapterID": "mutant"})
	c.call("launch", map[string]any{"program": program, "stopOnEntry": stopOnEntry})
	c.event("initialized")
}

// ---------------------------------------------------------------- handshake

func TestTheAdapterAnswersInitializeWithWhatItCanDo(t *testing.T) {
	c := newClient(t, Options{})

	reply := c.call("initialize", map[string]any{"adapterID": "mutant"})

	var caps capabilities
	c.body(reply, &caps)

	if !caps.SupportsConfigurationDoneRequest {
		t.Error("the adapter does not ask for configurationDone, so it would start before the breakpoints arrive")
	}
	if !caps.SupportsHitConditionalBreakpoints {
		t.Error("hit counts are supported by the engine but not advertised")
	}
	if caps.SupportsSetVariable {
		t.Error("setVariable is advertised but nothing implements it")
	}
}

// The initialized event has to follow the launch, not the initialize: a client
// sends its breakpoints when it sees initialized, and a breakpoint can only be
// bound once there is a program to bind it against.
func TestInitializedFollowsTheLaunchSoBreakpointsCanBind(t *testing.T) {
	program := write(t, "prog.mut", "let a = 1;\nlet b = a + 1;\nb;\n")

	c := newClient(t, Options{})
	c.call("initialize", map[string]any{"adapterID": "mutant"})

	// Nothing has been launched, so a breakpoint has nothing to bind against
	// and the adapter says so rather than accepting it.
	early := c.response(c.request("setBreakpoints", map[string]any{
		"source":      map[string]any{"path": program},
		"breakpoints": []map[string]any{{"line": 2}},
	}))
	if early.Success {
		t.Error("breakpoints were accepted before a program was launched")
	}

	c.call("launch", map[string]any{"program": program})
	c.event("initialized")

	c.call("setBreakpoints", map[string]any{
		"source":      map[string]any{"path": program},
		"breakpoints": []map[string]any{{"line": 2}},
	})
}

// There is no separate process to attach to, and attaching an OS debugger to a
// running mutant is what its anti-reversing probes exist to stop.
func TestAttachIsRefusedWithTheReason(t *testing.T) {
	c := newClient(t, Options{})
	c.call("initialize", map[string]any{"adapterID": "mutant"})

	reply := c.response(c.request("attach", map[string]any{}))
	if reply.Success {
		t.Fatal("attach was accepted")
	}
	if !strings.Contains(reply.Message, "launch") {
		t.Errorf("the refusal does not name the alternative: %q", reply.Message)
	}
}

func TestAProgramThatWillNotParseFailsTheLaunch(t *testing.T) {
	program := write(t, "broken.mut", "let a = ;\n")

	c := newClient(t, Options{})
	c.call("initialize", map[string]any{"adapterID": "mutant"})

	reply := c.response(c.request("launch", map[string]any{"program": program}))
	if reply.Success {
		t.Fatal("a program that does not parse was launched")
	}
	if reply.Message == "" {
		t.Error("the launch failed with no explanation")
	}
}

func TestLaunchingWithNoProgramSaysSo(t *testing.T) {
	c := newClient(t, Options{})
	c.call("initialize", map[string]any{"adapterID": "mutant"})

	reply := c.response(c.request("launch", map[string]any{}))
	if reply.Success {
		t.Fatal("a launch with no program succeeded")
	}
	if !strings.Contains(reply.Message, ".mut") {
		t.Errorf("the refusal does not say what is missing: %q", reply.Message)
	}
}

// A client with nowhere to put the program in its configuration can pass it on
// the command line instead.
func TestTheCommandLineProgramIsTheDefault(t *testing.T) {
	program := write(t, "prog.mut", "let a = 1;\na;\n")

	c := newClient(t, Options{Program: program})
	c.call("initialize", map[string]any{"adapterID": "mutant"})
	c.call("launch", map[string]any{})
	c.event("initialized")
}

// A launched program runs with the tamper responses advisory, the way a program
// under `mutant test` does.
//
// It is the sandbox probe that makes this load-bearing. Malware is examined on a
// virtual machine, and so is every CI runner, and the detector cannot tell that
// VM from the one an adversary would use -- so in secure mode the probe fired on
// launch and ended the session before the first line was stepped. The probes are
// still compiled into the bytecode being stepped; only the response changes.
//
// The session is driven directly rather than through a client: this is about the
// machine the launch builds, and the wire has nothing to say about it.
func TestALaunchedProgramRunsWithAdvisoryTamperResponses(t *testing.T) {
	program := write(t, "posture.mut", "let a = 1;\na;\n")

	s := &session{conn: newConn(strings.NewReader(""), io.Discard), refs: make(map[int]varSource)}
	t.Cleanup(s.shutdown)

	if err := s.onLaunch(&request{
		Seq:       1,
		Type:      "request",
		Command:   "launch",
		Arguments: json.RawMessage(fmt.Sprintf(`{"program":%q}`, program)),
	}); err != nil {
		t.Fatalf("launch: %v", err)
	}

	if s.machine == nil {
		t.Fatal("the launch built no machine")
	}
	if s.machine.SecureMode() {
		t.Error("a debug session runs in secure mode: a sandbox probe hit ends it instead of warning")
	}
}

// ------------------------------------------------------------ a full session

func TestASessionStopsAtABreakpointAndReadsTheFrame(t *testing.T) {
	program := write(t, "prog.mut", "let scale = 3;\n"+ //     1
		"let tally = fn(xs, bump) {\n"+ //                     2
		"\tlet total = 0;\n"+ //                               3
		"\tfor (v in xs) {\n"+ //                              4
		"\t\ttotal = total + v * scale + bump;\n"+ //          5
		"\t}\n"+ //                                            6
		"\treturn total;\n"+ //                                7
		"};\n"+ //                                             8
		"let answer = tally([1, 2], 10);\n"+ //                9
		"answer;\n") //                                       10

	c := newClient(t, Options{})
	c.start(program, false)

	var setBody struct {
		Breakpoints []breakpoint `json:"breakpoints"`
	}
	c.body(c.call("setBreakpoints", map[string]any{
		"source":      map[string]any{"path": program},
		"breakpoints": []map[string]any{{"line": 7}},
	}), &setBody)

	if len(setBody.Breakpoints) != 1 || !setBody.Breakpoints[0].Verified {
		t.Fatalf("the breakpoint was not bound: %+v", setBody.Breakpoints)
	}
	if setBody.Breakpoints[0].Line != 7 {
		t.Errorf("the breakpoint bound to line %d, want 7", setBody.Breakpoints[0].Line)
	}

	c.call("configurationDone", map[string]any{})

	var stopped stoppedBody
	c.body(c.event("stopped"), &stopped)
	if stopped.Reason != "breakpoint" {
		t.Fatalf("stopped for %q, want breakpoint", stopped.Reason)
	}
	if len(stopped.HitBreakpointIDs) != 1 || stopped.HitBreakpointIDs[0] != setBody.Breakpoints[0].ID {
		t.Errorf("the stop names breakpoints %v, want [%d]", stopped.HitBreakpointIDs, setBody.Breakpoints[0].ID)
	}

	// The stack.
	var stack struct {
		StackFrames []stackFrame `json:"stackFrames"`
		TotalFrames int          `json:"totalFrames"`
	}
	c.body(c.call("stackTrace", map[string]any{"threadId": mainThreadID}), &stack)
	if len(stack.StackFrames) < 2 {
		t.Fatalf("the stack is %d deep inside a call", len(stack.StackFrames))
	}
	top := stack.StackFrames[0]
	if top.Line != 7 {
		t.Errorf("the top frame is on line %d, want 7", top.Line)
	}
	if top.Source == nil || !strings.HasSuffix(top.Source.Path, "prog.mut") {
		t.Errorf("the top frame names %+v, want the program", top.Source)
	}
	if !filepath.IsAbs(top.Source.Path) {
		t.Errorf("the editor was given a relative path: %q", top.Source.Path)
	}

	// Its scopes and values.
	var scopesBody struct {
		Scopes []scope `json:"scopes"`
	}
	c.body(c.call("scopes", map[string]any{"frameId": top.ID}), &scopesBody)

	byName := map[string]int{}
	for _, group := range scopesBody.Scopes {
		byName[group.Name] = group.VariablesReference
	}
	for _, want := range []string{"Arguments", "Locals", "Globals"} {
		if byName[want] == 0 {
			t.Fatalf("no %s scope: got %v", want, scopesBody.Scopes)
		}
	}

	values := c.variables(byName["Locals"])
	if values["total"].Value != "29" {
		t.Errorf("total is %q, want 29", values["total"].Value)
	}

	arguments := c.variables(byName["Arguments"])
	if arguments["xs"].VariablesReference == 0 {
		t.Fatal("the array argument offered no expansion")
	}
	elements := c.variables(arguments["xs"].VariablesReference)
	if elements["[1]"].Value != "2" {
		t.Errorf("xs[1] is %q, want 2", elements["[1]"].Value)
	}

	// A name can be evaluated; an expression cannot, and says why.
	var evaluated struct {
		Result string `json:"result"`
	}
	c.body(c.call("evaluate", map[string]any{
		"expression": "scale", "frameId": top.ID, "context": "watch",
	}), &evaluated)
	if evaluated.Result != "3" {
		t.Errorf("scale evaluated to %q, want 3", evaluated.Result)
	}

	refused := c.response(c.request("evaluate", map[string]any{
		"expression": "total + 1", "frameId": top.ID, "context": "watch",
	}))
	if refused.Success {
		t.Error("an expression was evaluated")
	}

	c.call("continue", map[string]any{"threadId": mainThreadID})

	var exited exitedBody
	c.body(c.event("exited"), &exited)
	if exited.ExitCode != 0 {
		t.Errorf("the program exited %d, want 0", exited.ExitCode)
	}
	c.event("terminated")
}

// variables reads one reference and returns its contents by name.
func (c *client) variables(reference int) map[string]variable {
	c.t.Helper()

	var body struct {
		Variables []variable `json:"variables"`
	}
	c.body(c.call("variables", map[string]any{"variablesReference": reference}), &body)

	out := make(map[string]variable, len(body.Variables))
	for _, v := range body.Variables {
		out[v.Name] = v
	}
	return out
}

func TestSteppingWalksTheProgram(t *testing.T) {
	program := write(t, "prog.mut", "let helper = fn(x) {\n"+ // 1
		"\tlet bumped = x + 1;\n"+ //                            2
		"\treturn bumped;\n"+ //                                 3
		"};\n"+ //                                               4
		"let a = helper(1);\n"+ //                               5
		"let b = a + 1;\n"+ //                                   6
		"b;\n") //                                               7

	c := newClient(t, Options{})
	c.start(program, false)
	c.call("setBreakpoints", map[string]any{
		"source":      map[string]any{"path": program},
		"breakpoints": []map[string]any{{"line": 5}},
	})
	c.call("configurationDone", map[string]any{})

	var stopped stoppedBody
	c.body(c.event("stopped"), &stopped)

	// Into the callee.
	c.call("stepIn", map[string]any{"threadId": mainThreadID})
	c.body(c.event("stopped"), &stopped)
	if stopped.Reason != "step" {
		t.Fatalf("stopped for %q, want step", stopped.Reason)
	}
	if line := c.topLine(); line != 2 {
		t.Errorf("stepIn landed on line %d, want the callee's line 2", line)
	}

	// Back out to the caller.
	c.call("stepOut", map[string]any{"threadId": mainThreadID})
	c.body(c.event("stopped"), &stopped)
	if name := c.topFunction(); strings.HasPrefix(name, "helper") {
		t.Errorf("stepOut stayed in %q", name)
	}

	c.call("continue", map[string]any{"threadId": mainThreadID})
	c.event("terminated")
}

func (c *client) topLine() int {
	c.t.Helper()
	return c.topFrame().Line
}

func (c *client) topFunction() string {
	c.t.Helper()
	return c.topFrame().Name
}

func (c *client) topFrame() stackFrame {
	c.t.Helper()

	var stack struct {
		StackFrames []stackFrame `json:"stackFrames"`
	}
	c.body(c.call("stackTrace", map[string]any{"threadId": mainThreadID}), &stack)
	if len(stack.StackFrames) == 0 {
		c.t.Fatal("the stack is empty")
	}
	return stack.StackFrames[0]
}

// Program output has to reach the client as events rather than as bytes on the
// transport. An adapter whose debuggee writes to its own stream corrupts every
// message after the first putln, which is the failure this test would catch:
// nothing after it would decode at all.
func TestProgramOutputArrivesAsEventsAndNotOnTheWire(t *testing.T) {
	program := write(t, "prog.mut", "putln(\"hello from the program\");\n1;\n")

	c := newClient(t, Options{})
	c.start(program, false)
	c.call("configurationDone", map[string]any{})

	var printed strings.Builder
	for {
		msg := c.next()
		if msg.Type == "event" && msg.Event == "output" {
			var body outputBody
			c.body(msg, &body)
			printed.WriteString(body.Output)
			continue
		}
		if msg.Type == "event" && msg.Event == "terminated" {
			break
		}
	}

	if !strings.Contains(printed.String(), "hello from the program") {
		t.Errorf("the program's output never arrived: %q", printed.String())
	}
	// `mutant run` prints the program's value; a session that steps it to the
	// end shows the same thing.
	if !strings.Contains(printed.String(), "1") {
		t.Errorf("the program's result never arrived: %q", printed.String())
	}
}

func TestAFailingProgramReportsTheTracebackAndANonZeroExit(t *testing.T) {
	program := write(t, "prog.mut", "let f = fn(x) {\n\treturn x / 0;\n};\nf(1);\n")

	c := newClient(t, Options{})
	c.start(program, false)
	c.call("configurationDone", map[string]any{})

	var stderr strings.Builder
	var exited exitedBody
	sawExit := false

	for {
		msg := c.next()
		switch {
		case msg.Type == "event" && msg.Event == "output":
			var body outputBody
			c.body(msg, &body)
			if body.Category == "stderr" {
				stderr.WriteString(body.Output)
			}
		case msg.Type == "event" && msg.Event == "exited":
			c.body(msg, &exited)
			sawExit = true
		case msg.Type == "event" && msg.Event == "terminated":
			if !sawExit {
				t.Fatal("the session terminated without reporting an exit code")
			}
			if exited.ExitCode == 0 {
				t.Error("a program that failed exited 0")
			}
			if !strings.Contains(stderr.String(), "at ") {
				t.Errorf("the failure carried no traceback: %q", stderr.String())
			}
			return
		}
	}
}

// -------------------------------------------------------------- breakpoints

func TestBreakpointLocationsReportWhereAMarkerCanLand(t *testing.T) {
	program := write(t, "prog.mut", "let a = 1;\n"+ // 1
		"\n"+ //                                       2
		"// nothing here\n"+ //                        3
		"let b = a + 1;\n"+ //                         4
		"b;\n") //                                     5

	c := newClient(t, Options{})
	c.start(program, false)

	var body struct {
		Breakpoints []breakpointLocation `json:"breakpoints"`
	}
	c.body(c.call("breakpointLocations", map[string]any{
		"source": map[string]any{"path": program}, "line": 1, "endLine": 5,
	}), &body)

	lines := map[int]bool{}
	for _, location := range body.Breakpoints {
		lines[location.Line] = true
	}
	if !lines[1] || !lines[4] {
		t.Errorf("lines with code are reported as %v, want 1 and 4 among them", lines)
	}
	if lines[2] || lines[3] {
		t.Errorf("a blank line or a comment was offered as a breakpoint site: %v", lines)
	}
}

// A breakpoint whose condition cannot be honoured stays armed and says so. A
// breakpoint that silently never fires is the worse of the two failures.
func TestAnUnsupportedConditionArmsTheBreakpointAndExplains(t *testing.T) {
	program := write(t, "prog.mut", "let a = 1;\nlet b = 2;\nb;\n")

	c := newClient(t, Options{})
	c.start(program, false)

	var body struct {
		Breakpoints []breakpoint `json:"breakpoints"`
	}
	c.body(c.call("setBreakpoints", map[string]any{
		"source":      map[string]any{"path": program},
		"breakpoints": []map[string]any{{"line": 2, "condition": "a > 0"}},
	}), &body)

	if !body.Breakpoints[0].Verified {
		t.Fatal("a conditional breakpoint was dropped rather than armed")
	}
	if !strings.Contains(body.Breakpoints[0].Message, "condition") {
		t.Errorf("the breakpoint does not explain itself: %q", body.Breakpoints[0].Message)
	}

	c.call("configurationDone", map[string]any{})
	c.event("stopped")
	c.call("continue", map[string]any{"threadId": mainThreadID})
	c.event("terminated")
}

func TestHitConditionsAreReadTheWayClientsWriteThem(t *testing.T) {
	cases := []struct {
		condition string
		skip      int
		ok        bool
	}{
		{condition: "1", skip: 0, ok: true},
		{condition: "5", skip: 4, ok: true},
		{condition: " 5 ", skip: 4, ok: true},
		{condition: "==5", skip: 4, ok: true},
		{condition: "=5", skip: 4, ok: true},
		{condition: ">=5", skip: 4, ok: true},
		{condition: ">5", skip: 5, ok: true},
		{condition: "> 5", skip: 5, ok: true},
		{condition: "0", ok: false},
		{condition: "", ok: false},
		{condition: "x > 5", ok: false},
		{condition: "%3", ok: false},
	}

	for _, tc := range cases {
		skip, ok := parseHitCondition(tc.condition)
		if ok != tc.ok {
			t.Errorf("%q was %s, want the opposite", tc.condition, readability(ok))
			continue
		}
		if ok && skip != tc.skip {
			t.Errorf("%q skips %d arrivals, want %d", tc.condition, skip, tc.skip)
		}
	}
}

func readability(ok bool) string {
	if ok {
		return "understood"
	}
	return "refused"
}

// ------------------------------------------------------------------ control

func TestStoppingOnEntryParksBeforeAnythingRuns(t *testing.T) {
	program := write(t, "prog.mut", "let a = 1;\nlet b = 2;\nb;\n")

	c := newClient(t, Options{})
	c.start(program, true)
	c.call("configurationDone", map[string]any{})

	var stopped stoppedBody
	c.body(c.event("stopped"), &stopped)
	if stopped.Reason != "entry" {
		t.Fatalf("stopped for %q, want entry", stopped.Reason)
	}
	if line := c.topLine(); line != 1 {
		t.Errorf("the entry stop is on line %d, want 1", line)
	}

	c.call("continue", map[string]any{"threadId": mainThreadID})
	c.event("terminated")
}

// A reference is only meaningful at the stop that issued it, and one used later
// has to be refused rather than answered with whatever now holds that number.
func TestAStaleVariablesReferenceIsRefused(t *testing.T) {
	program := write(t, "prog.mut", "let xs = [1, 2];\nlet a = 1;\nlet b = 2;\nb;\n")

	c := newClient(t, Options{})
	c.start(program, false)
	c.call("setBreakpoints", map[string]any{
		"source":      map[string]any{"path": program},
		"breakpoints": []map[string]any{{"line": 2}, {"line": 3}},
	})
	c.call("configurationDone", map[string]any{})
	c.event("stopped")

	frame := c.topFrame()
	var scopesBody struct {
		Scopes []scope `json:"scopes"`
	}
	c.body(c.call("scopes", map[string]any{"frameId": frame.ID}), &scopesBody)

	stale := 0
	for _, group := range scopesBody.Scopes {
		if group.Name == "Globals" {
			stale = group.VariablesReference
		}
	}
	if stale == 0 {
		t.Fatal("no globals scope to go stale")
	}

	c.call("continue", map[string]any{"threadId": mainThreadID})
	c.event("stopped")

	reply := c.response(c.request("variables", map[string]any{"variablesReference": stale}))
	if reply.Success {
		t.Error("a reference from the previous stop still resolved")
	}

	c.call("continue", map[string]any{"threadId": mainThreadID})
	c.event("terminated")
}

func TestDisconnectEndsTheSession(t *testing.T) {
	program := write(t, "prog.mut", "let i = 0;\nwhile (i < 2000000) {\n\ti = i + 1;\n}\ni;\n")

	c := newClient(t, Options{})
	c.start(program, true)
	c.call("configurationDone", map[string]any{})
	c.event("stopped")

	c.call("disconnect", map[string]any{})

	select {
	case err := <-c.served:
		if err != nil {
			t.Fatalf("the session ended with %v", err)
		}
	case <-time.After(messageTimeout):
		t.Fatal("the adapter did not return after a disconnect")
	}
}

func TestAnUnknownRequestIsRefusedByName(t *testing.T) {
	c := newClient(t, Options{})
	c.call("initialize", map[string]any{"adapterID": "mutant"})

	reply := c.response(c.request("gotoTargets", map[string]any{}))
	if reply.Success {
		t.Fatal("an unimplemented request was accepted")
	}
	if !strings.Contains(reply.Message, "gotoTargets") {
		t.Errorf("the refusal does not name the request: %q", reply.Message)
	}
}

// ---------------------------------------------------------------- transport

// A Content-Length that does not match the body, or one large enough to be an
// attack on the allocator, has to end the session rather than be honoured.
func TestTheTransportRefusesAnImpossibleFrame(t *testing.T) {
	cases := map[string]string{
		"no length":    "Content-Type: application/json\r\n\r\n{}",
		"unreadable":   "Content-Length: banana\r\n\r\n{}",
		"absurd":       fmt.Sprintf("Content-Length: %d\r\n\r\n{}", maxMessageBytes+1),
		"header split": "Content-Length 12\r\n\r\n{}",
	}

	for name, frame := range cases {
		c := newConn(strings.NewReader(frame), io.Discard)
		if _, err := c.read(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// A message that is not a request is skipped rather than refused: a client may
// send events of its own, and an adapter that fell over on one would be brittle
// for no gain.
func TestTheTransportSkipsMessagesThatAreNotRequests(t *testing.T) {
	frames := frame(`{"seq":1,"type":"event","event":"noise"}`) +
		frame(`{"seq":2,"type":"request","command":"initialize"}`)

	c := newConn(strings.NewReader(frames), io.Discard)
	req, err := c.read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if req.Command != "initialize" {
		t.Errorf("read %q, want the request that followed the event", req.Command)
	}
}

func frame(payload string) string {
	return fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(payload), payload)
}
