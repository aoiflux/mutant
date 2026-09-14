package vm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"mutant/compiler"
	"mutant/global"
	"mutant/mutil"
	"mutant/object"
	"mutant/security"
)

// stopTimeout bounds every wait for an event. A handshake bug between the
// executor goroutine and the consumer would otherwise hang the whole package's
// test run with no indication of which test did it.
const stopTimeout = 30 * time.Second

// session drives one debug session from the test goroutine.
type session struct {
	t   *testing.T
	vm  *VM
	dbg *Debugger
}

// newSession compiles src the way the generator does -- positions on, then
// sealed -- attaches a debugger and starts the program.
//
// Sealing is not incidental: stack values live encrypted at rest, so a debugger
// that read the stack directly would render ciphertext. Running the tests
// against the sealed program is what proves it goes through decryptForUse the
// way every other reader does.
func newSession(t *testing.T, src string, options DebugOptions) *session {
	t.Helper()
	return newSessionFromBytecode(t, compilePositioned(t, src), options)
}

func newSessionFromBytecode(t *testing.T, bc *compiler.ByteCode, options DebugOptions) *session {
	t.Helper()

	password := fmt.Sprint(security.DerivePasswordFromInstructions(bc.Instructions))
	bc = mutil.EncryptByteCode(bc, password)
	machine := NewWithGlobalStoreAndPassword(bc, make([]object.Object, global.GlobalSize), password)

	dbg, err := NewDebugger(machine, options)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	t.Cleanup(dbg.Terminate)

	// Attached, not started. Starting here would race every test that sets a
	// breakpoint on the next line: the executor runs on its own goroutine and
	// these programs finish in microseconds, so whether the breakpoint was
	// armed in time came down to the scheduler. It surfaced as a stray
	// `stopped for "exited", want "breakpoint"` under the load of a full test
	// run, and passed every time the test was looked at on its own.
	//
	// The adapter has the same problem and answers it the same way: dap's
	// session calls Run from onConfigurationDone, once the editor has sent
	// every breakpoint it has. The first wait is this harness's
	// configurationDone.
	return &session{t: t, vm: machine, dbg: dbg}
}

// start runs the program. Run is idempotent, so every wait calls it and a
// test only calls it directly when it needs the program moving before it waits
// for anything.
func (s *session) start() {
	s.t.Helper()
	s.dbg.Run()
}

// next waits for the session's next stop, starting the program if nothing has
// yet -- see newSessionFromBytecode for why that does not happen at attach time.
func (s *session) next() Stop {
	s.t.Helper()
	s.start()

	select {
	case stop, open := <-s.dbg.Events():
		if !open {
			s.t.Fatal("the event channel closed without reporting an exit")
		}
		return stop
	case <-time.After(stopTimeout):
		s.t.Fatal("the debugger never reported a stop")
		return Stop{}
	}
}

// expect waits for the next stop and insists on its reason.
func (s *session) expect(reason StopReason) Stop {
	s.t.Helper()

	stop := s.next()
	if stop.Reason != reason {
		s.t.Fatalf("stopped for %q, want %q (error: %v)", stop.Reason, reason, stop.Err)
	}
	return stop
}

// line is the file line the innermost frame is parked on.
func (s *session) line() int {
	s.t.Helper()

	frames, err := s.dbg.Frames()
	if err != nil {
		s.t.Fatalf("frames: %v", err)
	}
	if len(frames) == 0 {
		s.t.Fatal("the stack is empty while stopped")
	}
	return frames[0].Line
}

// function is the name of the innermost frame's function.
func (s *session) function() string {
	s.t.Helper()

	frames, err := s.dbg.Frames()
	if err != nil {
		s.t.Fatalf("frames: %v", err)
	}
	return frames[0].Function
}

// variable finds a named value in a scope of the innermost frame.
func (s *session) variable(scope, name string) Variable {
	s.t.Helper()

	scopes, err := s.dbg.Scopes(0)
	if err != nil {
		s.t.Fatalf("scopes: %v", err)
	}
	for _, group := range scopes {
		if group.Name != scope {
			continue
		}
		for _, v := range group.Variables {
			if v.Name == name {
				return v
			}
		}
		s.t.Fatalf("%s holds %s, not %s", scope, strings.Join(variableNames(group.Variables), ", "), name)
	}
	s.t.Fatalf("there is no %s scope here", scope)
	return Variable{}
}

func variableNames(vars []Variable) []string {
	names := make([]string, 0, len(vars))
	for _, v := range vars {
		names = append(names, v.Name)
	}
	return names
}

func (s *session) breakAt(file string, lines ...int) []Breakpoint {
	s.t.Helper()

	specs := make([]BreakpointSpec, 0, len(lines))
	for _, line := range lines {
		specs = append(specs, BreakpointSpec{Line: line})
	}
	bps, err := s.dbg.SetBreakpoints(file, specs)
	if err != nil {
		s.t.Fatalf("set breakpoints: %v", err)
	}
	return bps
}

// ---------------------------------------------------------------- attaching

// A release artifact has no positions, so there is no line to stop on and no
// name for any slot -- and rendering the values held by a program that left
// this machine is the disclosure frameArguments already declines to make.
func TestADebuggerRefusesAProgramWithNoPositions(t *testing.T) {
	bc := compilePositioned(t, "let a = 1;\na;\n")
	bc.StripDebugInfo()

	machine := NewWithGlobalStore(bc, make([]object.Object, global.GlobalSize))
	if _, err := NewDebugger(machine, DebugOptions{}); !errors.Is(err, ErrNoDebugInfo) {
		t.Fatalf("attaching to a stripped program returned %v, want ErrNoDebugInfo", err)
	}
}

func TestOnlyOneDebuggerCanAttach(t *testing.T) {
	machine := NewWithGlobalStore(compilePositioned(t, "let a = 1;\na;\n"), make([]object.Object, global.GlobalSize))

	if _, err := NewDebugger(machine, DebugOptions{}); err != nil {
		t.Fatalf("first attach: %v", err)
	}
	if _, err := NewDebugger(machine, DebugOptions{}); err == nil {
		t.Fatal("a second debugger attached to the same VM")
	}
}

// ------------------------------------------------------------------ running

func TestAProgramWithNoBreakpointsRunsToCompletion(t *testing.T) {
	s := newSession(t, "let a = 1;\nlet b = a + 1;\nb;\n", DebugOptions{})

	stop := s.expect(StopExited)
	if stop.Err != nil {
		t.Fatalf("the program failed: %v", stop.Err)
	}
}

// The run's outcome is reported as the exit event rather than swallowed: a
// session that ends in a crash has to say so, with the traceback the VM built.
func TestARuntimeFailureIsReportedAsTheOutcome(t *testing.T) {
	s := newSession(t, "let f = fn(x) {\n\treturn x / 0;\n};\nf(1);\n", DebugOptions{})

	stop := s.expect(StopExited)
	if stop.Err == nil {
		t.Fatal("a division by zero was reported as a clean exit")
	}

	var runtimeErr *RuntimeError
	if !errors.As(stop.Err, &runtimeErr) {
		t.Fatalf("the failure carries no traceback: %v", stop.Err)
	}
	if len(runtimeErr.Frames) == 0 {
		t.Error("the traceback has no frames")
	}
}

func TestStoppingOnEntryParksBeforeTheFirstInstruction(t *testing.T) {
	s := newSession(t, "let a = 1;\nlet b = 2;\nb;\n", DebugOptions{StopOnEntry: true})

	s.expect(StopEntry)
	if line := s.line(); line != 1 {
		t.Errorf("the entry stop is on line %d, want 1", line)
	}

	// Nothing has run, so the first binding does not exist yet.
	scopes, err := s.dbg.Scopes(0)
	if err != nil {
		t.Fatalf("scopes: %v", err)
	}
	for _, scope := range scopes {
		if scope.Name == "Globals" && len(scope.Variables) > 0 {
			t.Errorf("a global exists before the first instruction ran: %v", variableNames(scope.Variables))
		}
	}

	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopExited)
}

// An attached debugger must not change what the program computes. clearUnsetLocals
// writes to the frame's slots, which is the one thing here that touches state
// the program can see.
func TestAnAttachedDebuggerDoesNotChangeTheAnswer(t *testing.T) {
	src := "let make = fn(base) {\n" +
		"\tlet acc = base;\n" +
		"\tlet add = fn(n) {\n" +
		"\t\tacc = acc + n;\n" +
		"\t\treturn acc;\n" +
		"\t};\n" +
		"\tadd(2);\n" +
		"\tadd(3);\n" +
		"\treturn acc;\n" +
		"};\n" +
		"let answer = make(10);\n" +
		"answer;\n"

	plain, plainErr := runSealed(t, compilePositioned(t, src))
	if plainErr != nil {
		t.Fatalf("the undebugged run failed: %v", plainErr)
	}

	s := newSession(t, src, DebugOptions{})
	if stop := s.expect(StopExited); stop.Err != nil {
		t.Fatalf("the debugged run failed: %v", stop.Err)
	}

	want := plain.LastPoppedStackElement()
	got := s.vm.LastPoppedStackElement()
	if want == nil || got == nil {
		t.Fatal("one of the runs left no value behind")
	}
	if want.Inspect() != got.Inspect() {
		t.Errorf("the debugged run answered %s, the plain run %s", got.Inspect(), want.Inspect())
	}
}

// -------------------------------------------------------------- breakpoints

func TestABreakpointStopsOnItsLine(t *testing.T) {
	src := "let f = fn(x) {\n" + // 1
		"\tlet doubled = x * 2;\n" + // 2
		"\treturn doubled;\n" + //      3
		"};\n" + //                     4
		"f(21);\n" //                   5

	s := newSession(t, src, DebugOptions{})

	bps := s.breakAt("prog.mut", 3)
	if len(bps) != 1 || !bps[0].Verified {
		t.Fatalf("the breakpoint was not bound: %+v", bps)
	}
	if bps[0].Line != 3 {
		t.Errorf("the breakpoint reports line %d, want 3", bps[0].Line)
	}

	stop := s.expect(StopBreakpoint)
	if stop.Breakpoint.ID != bps[0].ID {
		t.Errorf("stopped at breakpoint %d, want %d", stop.Breakpoint.ID, bps[0].ID)
	}
	if line := s.line(); line != 3 {
		t.Errorf("stopped on line %d, want 3", line)
	}
	if fn := s.function(); fn != "f" {
		t.Errorf("stopped in %q, want f", fn)
	}

	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopExited)
}

// A marker on a blank line or a comment has to land somewhere, and the editor
// has to be told where, or it shows the marker on one line while the program
// stops on another.
func TestABreakpointOnALineWithNoCodeBindsForward(t *testing.T) {
	src := "let a = 1;\n" + //  1
		"\n" + //               2  blank
		"// a comment\n" + //   3
		"let b = a + 1;\n" + // 4
		"b;\n" //               5

	s := newSession(t, src, DebugOptions{})

	bps := s.breakAt("prog.mut", 2)
	if len(bps) != 1 || !bps[0].Verified {
		t.Fatalf("the breakpoint was not bound: %+v", bps)
	}
	if bps[0].Line != 4 {
		t.Errorf("a breakpoint asked for on line 2 reports line %d, want 4", bps[0].Line)
	}

	s.expect(StopBreakpoint)
	if line := s.line(); line != 4 {
		t.Errorf("stopped on line %d, want 4", line)
	}

	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopExited)
}

// Past the last line that emitted an instruction there is nothing to stop at.
// Reporting the breakpoint as unverified is the difference between an editor
// showing a hollow marker and one showing a solid marker that never fires.
func TestABreakpointPastTheEndIsReportedUnverified(t *testing.T) {
	s := newSession(t, "let a = 1;\na;\n", DebugOptions{})

	bps := s.breakAt("prog.mut", 99)
	if len(bps) != 1 {
		t.Fatalf("got %d breakpoints", len(bps))
	}
	if bps[0].Verified {
		t.Error("a breakpoint past the end of the program was verified")
	}
	if bps[0].Message == "" {
		t.Error("an unverified breakpoint gave no reason")
	}

	s.expect(StopExited)
}

func TestABreakpointInAFileTheProgramDoesNotContainIsRefused(t *testing.T) {
	src := "let boom = fn() {\n\treturn 1;\n};\nboom();\n"
	spans := []compiler.ModuleSpan{{Path: "lib.mut", StartLine: 1}}

	s := newSessionFromBytecode(t, compileLinked(t, src, spans), DebugOptions{})

	bps := s.breakAt("nowhere.mut", 2)
	if bps[0].Verified {
		t.Error("a breakpoint in an unknown file was verified")
	}
	if !strings.Contains(bps[0].Message, "nowhere.mut") {
		t.Errorf("the reason does not name the file: %q", bps[0].Message)
	}

	s.expect(StopExited)
}

// A linked program's tables are keyed by the blob's lines, and the editor knows
// only its own file's. Getting the mapping backwards puts the breakpoint in
// another module at the same offset -- a plausible, confident, wrong stop.
func TestABreakpointInAModuleUsesThatModulesLines(t *testing.T) {
	// lib.mut is lines 1-3 of the blob, main.mut lines 4-6.
	src := "let helper = fn(x) {\n" + // 1  lib.mut:1
		"\treturn x + 1;\n" + //         2  lib.mut:2
		"};\n" + //                      3  lib.mut:3
		"let call = fn() {\n" + //       4  main.mut:1
		"\treturn helper(1);\n" + //     5  main.mut:2
		"};\n" + //                      6  main.mut:3
		"call();\n" //                   7  main.mut:4

	spans := []compiler.ModuleSpan{
		{Path: "lib.mut", StartLine: 1},
		{Path: "main.mut", StartLine: 4},
	}

	s := newSessionFromBytecode(t, compileLinked(t, src, spans), DebugOptions{})

	// lib.mut:2 is blob line 2 -- and main.mut:2 is blob line 5, which is what a
	// mapping that ignored the file would have armed.
	bps := s.breakAt("lib.mut", 2)
	if !bps[0].Verified {
		t.Fatalf("the breakpoint was not bound: %+v", bps[0])
	}

	s.expect(StopBreakpoint)

	frames, err := s.dbg.Frames()
	if err != nil {
		t.Fatalf("frames: %v", err)
	}
	if frames[0].File != "lib.mut" || frames[0].Line != 2 {
		t.Errorf("stopped at %s:%d, want lib.mut:2", frames[0].File, frames[0].Line)
	}

	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopExited)
}

// Setting a file's breakpoints replaces that file's set and leaves every other
// file alone, which is DAP's model and the only one that cannot drift out of
// step with the markers a user can see.
func TestSettingBreakpointsReplacesThatFilesSet(t *testing.T) {
	src := "let a = 1;\nlet b = 2;\nlet c = 3;\nc;\n"
	s := newSession(t, src, DebugOptions{})

	s.breakAt("prog.mut", 2)
	s.breakAt("prog.mut", 3) // replaces line 2's

	s.expect(StopBreakpoint)
	if line := s.line(); line != 3 {
		t.Errorf("stopped on line %d; the replaced breakpoint on line 2 is still armed", line)
	}

	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopExited)
}

// A hit count is the one breakpoint condition this engine takes, because it is
// the one that is not an expression.
func TestABreakpointCanSkipItsFirstArrivals(t *testing.T) {
	src := "let total = 0;\n" + //          1
		"for (v in [10, 20, 30, 40]) {\n" + // 2
		"\ttotal = total + v;\n" + //          3
		"}\n" + //                             4
		"total;\n" //                          5

	s := newSession(t, src, DebugOptions{})

	bps, err := s.dbg.SetBreakpoints("prog.mut", []BreakpointSpec{{Line: 3, SkipHits: 2}})
	if err != nil {
		t.Fatalf("set breakpoints: %v", err)
	}
	if !bps[0].Verified {
		t.Fatalf("the breakpoint was not bound: %+v", bps[0])
	}

	stop := s.expect(StopBreakpoint)
	if hits := stop.Breakpoint.Hits(); hits != 3 {
		t.Errorf("stopped on hit %d, want the third", hits)
	}

	// Two additions have already happened, so the running total is 10+20.
	if v := s.variable("Globals", "total"); v.Value != "30" {
		t.Errorf("total is %s at the third iteration, want 30", v.Value)
	}

	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopBreakpoint) // the fourth arrival
	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopExited)
}

// ----------------------------------------------------------------- stepping

func TestSteppingOverACallStaysInTheCallersFrame(t *testing.T) {
	src := "let helper = fn(x) {\n" + // 1
		"\tlet bumped = x + 1;\n" + //   2
		"\treturn bumped;\n" + //        3
		"};\n" + //                      4
		"let a = helper(1);\n" + //      5
		"let b = a + 1;\n" + //          6
		"b;\n" //                        7

	s := newSession(t, src, DebugOptions{})
	s.breakAt("prog.mut", 5)
	s.expect(StopBreakpoint)

	if err := s.dbg.Next(); err != nil {
		t.Fatalf("next: %v", err)
	}
	s.expect(StopStep)

	if fn := s.function(); fn == "helper" {
		t.Fatal("step-over walked into the call")
	}
	if line := s.line(); line != 6 {
		t.Errorf("stepped to line %d, want 6", line)
	}

	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopExited)
}

func TestSteppingInEntersTheCallee(t *testing.T) {
	src := "let helper = fn(x) {\n" + // 1
		"\tlet bumped = x + 1;\n" + //   2
		"\treturn bumped;\n" + //        3
		"};\n" + //                      4
		"let a = helper(1);\n" + //      5
		"a;\n" //                        6

	s := newSession(t, src, DebugOptions{})
	s.breakAt("prog.mut", 5)
	s.expect(StopBreakpoint)

	if err := s.dbg.StepIn(); err != nil {
		t.Fatalf("step in: %v", err)
	}
	s.expect(StopStep)

	if fn := s.function(); fn != "helper" {
		t.Fatalf("stepped into %q, want helper", fn)
	}
	if line := s.line(); line != 2 {
		t.Errorf("stepped to line %d, want the callee's first line 2", line)
	}

	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopExited)
}

func TestSteppingOutReturnsToTheCaller(t *testing.T) {
	src := "let helper = fn(x) {\n" + // 1
		"\tlet bumped = x + 1;\n" + //   2
		"\treturn bumped;\n" + //        3
		"};\n" + //                      4
		"let a = helper(1);\n" + //      5
		"let b = a + 1;\n" + //          6
		"b;\n" //                        7

	s := newSession(t, src, DebugOptions{})
	s.breakAt("prog.mut", 2)
	s.expect(StopBreakpoint)
	if fn := s.function(); fn != "helper" {
		t.Fatalf("the breakpoint landed in %q, want helper", fn)
	}

	if err := s.dbg.StepOut(); err != nil {
		t.Fatalf("step out: %v", err)
	}
	s.expect(StopStep)

	if fn := s.function(); fn == "helper" {
		t.Fatal("step-out left us in the frame it was asked to leave")
	}

	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopExited)
}

// A step is a source-line step, not an instruction step: one line is many
// instructions, and stopping on each of them would make a debugger useless.
func TestSteppingWalksLinesRatherThanInstructions(t *testing.T) {
	src := "let a = 1 + 2 * 3 - 4;\n" + // 1
		"let b = a * a + a;\n" + //        2
		"let c = b + 1;\n" + //            3
		"c;\n" //                          4

	s := newSession(t, src, DebugOptions{StopOnEntry: true})
	s.expect(StopEntry)

	seen := []int{s.line()}
	for i := 0; i < 3; i++ {
		if err := s.dbg.Next(); err != nil {
			t.Fatalf("next: %v", err)
		}
		stop := s.next()
		if stop.Reason == StopExited {
			break
		}
		seen = append(seen, s.line())
	}

	want := []int{1, 2, 3, 4}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Errorf("stepping visited %v, want %v", seen, want)
	}
}

// ------------------------------------------------------------------- values

const scopeProgram = "let scale = 3;\n" + //           1
	"let tally = fn(xs, bump) {\n" + //                2
	"\tlet total = 0;\n" + //                          3
	"\tfor (v in xs) {\n" + //                         4
	"\t\ttotal = total + v * scale + bump;\n" + //     5
	"\t}\n" + //                                       6
	"\treturn total;\n" + //                           7
	"};\n" + //                                        8
	"let answer = tally([1, 2], 10);\n" + //           9
	"answer;\n" //                                    10

func TestScopesNameArgumentsLocalsAndGlobals(t *testing.T) {
	s := newSession(t, scopeProgram, DebugOptions{})
	s.breakAt("prog.mut", 7)
	s.expect(StopBreakpoint)

	if v := s.variable("Arguments", "xs"); v.Value != "[1, 2]" {
		t.Errorf("xs is %q, want [1, 2]", v.Value)
	}
	if v := s.variable("Arguments", "bump"); v.Value != "10" {
		t.Errorf("bump is %q, want 10", v.Value)
	}
	if v := s.variable("Locals", "total"); v.Value != "29" {
		// 1*3+10 + 2*3+10
		t.Errorf("total is %q, want 29", v.Value)
	}
	if v := s.variable("Globals", "scale"); v.Value != "3" {
		t.Errorf("scale is %q, want 3", v.Value)
	}

	// An argument is a local slot too, but listing it in both panes would show
	// the same value twice under the same name.
	scopes, err := s.dbg.Scopes(0)
	if err != nil {
		t.Fatalf("scopes: %v", err)
	}
	for _, scope := range scopes {
		if scope.Name != "Locals" {
			continue
		}
		for _, v := range scope.Variables {
			if v.Name == "xs" || v.Name == "bump" {
				t.Errorf("the argument %s is listed in Locals as well", v.Name)
			}
		}
	}

	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopExited)
}

// The calling convention leaves a frame's unassigned slots holding whatever the
// previous call left on the stack. Showing that would put a dead value from an
// unrelated frame under the name of a variable whose declaration has not run.
func TestALocalReadsAsUnsetBeforeItsDeclarationRuns(t *testing.T) {
	s := newSession(t, scopeProgram, DebugOptions{})
	s.breakAt("prog.mut", 3)
	s.expect(StopBreakpoint)

	if v := s.variable("Locals", "total"); v.Value != "<unset>" {
		t.Errorf("total reads as %q before its declaration runs, want <unset>", v.Value)
	}

	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopExited)
}

// A global that has not been assigned yet is left out rather than shown unset:
// the globals array is sized for the whole program, so every binding below the
// current line would otherwise appear as a variable that does not exist.
func TestAGlobalAppearsOnlyOnceItIsAssigned(t *testing.T) {
	s := newSession(t, scopeProgram, DebugOptions{})
	s.breakAt("prog.mut", 3)
	s.expect(StopBreakpoint)

	scopes, err := s.dbg.Scopes(0)
	if err != nil {
		t.Fatalf("scopes: %v", err)
	}
	for _, scope := range scopes {
		if scope.Name != "Globals" {
			continue
		}
		for _, v := range scope.Variables {
			if v.Name == "answer" {
				t.Error("answer is shown as a global before its declaration ran")
			}
		}
	}

	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopExited)
}

// A captured local lives in a cell that the frame slot and every closure over
// it share. The cell is a storage location, not a value, and showing one would
// put an address where the program sees a number.
func TestACapturedLocalShowsItsValueRatherThanItsCell(t *testing.T) {
	src := "let make = fn(base) {\n" + //    1
		"\tlet acc = base;\n" + //            2
		"\tlet add = fn(n) {\n" + //          3
		"\t\tacc = acc + n;\n" + //           4
		"\t\treturn acc;\n" + //              5
		"\t};\n" + //                         6
		"\tadd(5);\n" + //                    7
		"\treturn acc;\n" + //                8
		"};\n" + //                           9
		"make(10);\n" //                     10

	s := newSession(t, src, DebugOptions{})
	s.breakAt("prog.mut", 8)
	s.expect(StopBreakpoint)

	v := s.variable("Locals", "acc")
	if v.Value != "15" {
		t.Errorf("the captured local reads as %q, want 15", v.Value)
	}
	if v.Type == string(object.CELL_OBJ) {
		t.Error("the cell was shown instead of what is in it")
	}

	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopExited)
}

func TestContainersExpandThroughTheirHandles(t *testing.T) {
	src := "struct Point { x; y; };\n" + //      1
		"let xs = [1, 2, 3];\n" + //             2
		"let h = {\"b\": 2, \"a\": 1};\n" + //   3
		"let p = Point { x: 7, y: 8 };\n" + //   4
		"let done = 1;\n" + //                   5
		"done;\n" //                             6

	s := newSession(t, src, DebugOptions{})
	s.breakAt("prog.mut", 5)
	s.expect(StopBreakpoint)

	array := s.variable("Globals", "xs")
	if array.Ref == 0 {
		t.Fatal("an array offered no expansion")
	}
	children, err := s.dbg.Children(array.Ref)
	if err != nil {
		t.Fatalf("children: %v", err)
	}
	if names := variableNames(children); fmt.Sprint(names) != "[[0] [1] [2]]" {
		t.Errorf("the array expanded to %v", names)
	}
	if children[1].Value != "2" {
		t.Errorf("element 1 is %q, want 2", children[1].Value)
	}

	hash := s.variable("Globals", "h")
	hashChildren, err := s.dbg.Children(hash.Ref)
	if err != nil {
		t.Fatalf("children: %v", err)
	}
	if len(hashChildren) != 2 {
		t.Fatalf("the hash expanded to %d entries, want 2", len(hashChildren))
	}
	// Pairs is a Go map: without sorting, a variables pane would reshuffle
	// itself on every step.
	if hashChildren[0].Name >= hashChildren[1].Name {
		t.Errorf("hash keys came back unsorted: %v", variableNames(hashChildren))
	}

	point := s.variable("Globals", "p")
	fields, err := s.dbg.Children(point.Ref)
	if err != nil {
		t.Fatalf("children: %v", err)
	}
	if names := variableNames(fields); fmt.Sprint(names) != "[x y]" {
		t.Errorf("the struct expanded to %v, want [x y]", names)
	}

	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopExited)
}

// A handle into a value that has since been reassigned points at the wrong
// thing, so every handle dies at the resume that follows the stop it was
// issued at.
func TestHandlesDoNotSurviveAResume(t *testing.T) {
	src := "let xs = [1, 2];\nlet a = 1;\nlet b = 2;\nb;\n"

	s := newSession(t, src, DebugOptions{})
	s.breakAt("prog.mut", 2, 3)
	s.expect(StopBreakpoint)

	ref := s.variable("Globals", "xs").Ref
	if ref == 0 {
		t.Fatal("an array offered no expansion")
	}

	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopBreakpoint)

	if _, err := s.dbg.Children(ref); err == nil {
		t.Error("a handle from the previous stop still resolved")
	}

	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopExited)
}

// --------------------------------------------------------------- evaluating

func TestEvaluateAnswersANameAndRefusesAnExpression(t *testing.T) {
	s := newSession(t, scopeProgram, DebugOptions{})
	s.breakAt("prog.mut", 7)
	s.expect(StopBreakpoint)

	local, err := s.dbg.Evaluate(0, "total")
	if err != nil {
		t.Fatalf("evaluating a local: %v", err)
	}
	if local.Value != "29" {
		t.Errorf("total evaluated to %q, want 29", local.Value)
	}

	globalValue, err := s.dbg.Evaluate(0, "scale")
	if err != nil {
		t.Fatalf("evaluating a global: %v", err)
	}
	if globalValue.Value != "3" {
		t.Errorf("scale evaluated to %q, want 3", globalValue.Value)
	}

	if _, err := s.dbg.Evaluate(0, "total + 1"); err == nil {
		t.Error("an expression was evaluated; only a bare name is answerable")
	} else if !strings.Contains(err.Error(), "scope") {
		t.Errorf("the refusal does not say why: %v", err)
	}

	if _, err := s.dbg.Evaluate(0, "nosuchname"); err == nil {
		t.Error("a name that is not in scope was answered")
	}

	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopExited)
}

// A caller's frame is readable from a stop deeper in the stack, which is what
// makes a stack trace navigable rather than decorative.
func TestAnOuterFrameCanBeInspected(t *testing.T) {
	s := newSession(t, scopeProgram, DebugOptions{})
	s.breakAt("prog.mut", 7)
	s.expect(StopBreakpoint)

	frames, err := s.dbg.Frames()
	if err != nil {
		t.Fatalf("frames: %v", err)
	}
	if len(frames) < 2 {
		t.Fatalf("the stack is %d deep at a breakpoint inside a call", len(frames))
	}

	if _, err := s.dbg.Scopes(1); err != nil {
		t.Fatalf("the caller's frame could not be read: %v", err)
	}
	if _, err := s.dbg.Scopes(len(frames)); err == nil {
		t.Error("a frame past the bottom of the stack was read")
	}

	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.expect(StopExited)
}

// ------------------------------------------------------- control and safety

// Reading the stack from another goroutine while the executor is mid-instruction
// is a data race, and a debugger's wrong answer is worse than no answer.
func TestReadingStateWhileRunningIsRefused(t *testing.T) {
	s := newSession(t, "let a = 1;\na;\n", DebugOptions{})

	// This one asks its question before it waits for anything, so it has to
	// start the program itself. Whether the read lands mid-run or after the
	// exit is the scheduler's business: the refusal is the same either way,
	// and both are checked below.
	s.start()

	if _, err := s.dbg.Frames(); err == nil {
		t.Error("the stack was read while the program was running")
	} else if !errors.Is(err, ErrNotStopped) && !strings.Contains(err.Error(), "finished") {
		t.Errorf("unexpected refusal: %v", err)
	}

	s.expect(StopExited)

	if _, err := s.dbg.Frames(); err == nil {
		t.Error("the stack was read after the program finished")
	}
}

func TestPauseStopsARunningProgram(t *testing.T) {
	src := "let i = 0;\n" + //        1
		"while (i < 2000000) {\n" + // 2
		"\ti = i + 1;\n" + //          3
		"}\n" + //                     4
		"i;\n" //                      5

	s := newSession(t, src, DebugOptions{})

	// The breakpoint is what makes this deterministic: a pause requested the
	// instant the program starts lands somewhere in the first statement, and
	// the loop is what the pause is meant to be interrupting.
	s.breakAt("prog.mut", 3)
	s.expect(StopBreakpoint)

	if _, err := s.dbg.SetBreakpoints("prog.mut", nil); err != nil {
		t.Fatalf("clear breakpoints: %v", err)
	}
	if err := s.dbg.Continue(); err != nil {
		t.Fatalf("continue: %v", err)
	}
	s.dbg.Pause()

	stop := s.next()
	if stop.Reason != StopPause {
		t.Fatalf("the program reached %q rather than pausing", stop.Reason)
	}

	// Parked inside the loop, with the counter somewhere short of the end.
	if line := s.line(); line < 2 || line > 4 {
		t.Errorf("paused on line %d, which is outside the loop", line)
	}
	if v := s.variable("Globals", "i"); v.Value == "" {
		t.Error("the paused program reported no counter")
	}

	s.dbg.Terminate()
}

// A terminate has to unwind a running executor and unblock a parked one, from
// any goroutine, however many times it is called.
func TestTerminateEndsASessionFromEitherState(t *testing.T) {
	t.Run("while stopped", func(t *testing.T) {
		s := newSession(t, "let a = 1;\nlet b = 2;\nb;\n", DebugOptions{StopOnEntry: true})
		s.expect(StopEntry)

		s.dbg.Terminate()
		s.dbg.Terminate() // idempotent

		if err := s.dbg.Continue(); err == nil {
			t.Error("a terminated session accepted a resume")
		}
	})

	t.Run("while running", func(t *testing.T) {
		src := "let i = 0;\nwhile (i < 2000000) {\n\ti = i + 1;\n}\ni;\n"
		s := newSession(t, src, DebugOptions{StopOnEntry: true})
		s.expect(StopEntry)

		if err := s.dbg.Continue(); err != nil {
			t.Fatalf("continue: %v", err)
		}
		s.dbg.Terminate()

		// The executor unwinds rather than running to completion, and the
		// unwinding is not reported as a crash.
		deadline := time.After(stopTimeout)
		for {
			select {
			case stop, open := <-s.dbg.Events():
				if !open {
					return
				}
				if stop.Reason == StopExited && stop.Err != nil {
					t.Fatalf("terminating reported a failure: %v", stop.Err)
				}
			case <-deadline:
				t.Fatal("the executor did not unwind")
			}
		}
	})
}
