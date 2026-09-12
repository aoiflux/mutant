package vm

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"mutant/builtin"
	"mutant/global"
	"mutant/object"
	"mutant/security"
)

// The test framework's engine.
//
// The VM runs it for the reason builtin/testing.go gives: an assertion has to
// record what it saw somewhere that outlives the call -- a statement
// `assert_eq(a, b);` pops its result and moves on -- and it has to know where it
// was called from. The executor is the only thing that has either.
//
// Three shapes make the whole thing:
//
//   - A test is run where it is written. `test(name, fn)` calls fn then and
//     there, so a test file reads top to bottom like the program it is, a test
//     declared inside another is a subtest, and nothing has to re-enter a VM
//     whose Run has already returned.
//   - A failed assertion is a recorded fact, not a control-flow event. The
//     language has no exceptions and this does not invent one: the test keeps
//     running, and a test that wants to stop early returns.
//   - A test that dies is caught at the test boundary. CallClosureSync already
//     restores the frame and stack pointers when the closure it ran failed, so
//     one broken test costs its file no other test.

// TestFailure is one assertion that did not hold.
type TestFailure struct {
	// File and Line are where the assertion was written, resolved through the
	// line table and the module spans, so they name the file the reader has
	// open rather than an offset into the linked source blob. Both are zero for
	// a program compiled without positions.
	File string
	Line int

	Message string
}

func (f TestFailure) String() string {
	if f.File == "" || f.Line <= 0 {
		return f.Message
	}
	return fmt.Sprintf("%s:%d: %s", f.File, f.Line, f.Message)
}

// TestResult is one `test(...)` call, or the file's own top level when an
// assertion was made outside every test.
type TestResult struct {
	// Name is the full path of the test, subtests joined to their parents with
	// "/". It is empty for the top-level result, which the reporter names after
	// the file.
	Name  string
	Depth int

	Failures []TestFailure

	// Err is a runtime error that ended this test, positioned the way an
	// assertion failure is. A test can both fail an assertion and then die, and
	// reporting only one of the two would hide the half that explains the
	// other, so this is kept apart from Failures rather than appended to it.
	Err *TestFailure

	// Skipped is set for a test the run decided not to call: one the --run
	// filter did not select, or one reached after --fail-fast had already seen
	// a failure. A skipped test has passed nothing and failed nothing, so it is
	// reported as neither.
	Skipped bool

	// FailedChildren counts subtests that did not pass. A parent whose subtest
	// failed has failed, the way `go test` reports it, even when the parent
	// asserted nothing itself.
	FailedChildren int

	Elapsed time.Duration
}

func (r *TestResult) Passed() bool {
	return len(r.Failures) == 0 && r.Err == nil && r.FailedChildren == 0
}

// TestFilter selects which tests run, from a pattern like `--run Outer/Inner`.
//
// The pattern is split on "/" and each part is matched against the test at that
// nesting level, which is how `go test -run` reads and therefore how a reader
// will expect this to read. Beyond the last part everything matches: selecting
// a test selects everything inside it.
type TestFilter struct {
	parts []*regexp.Regexp
}

// NewTestFilter compiles a --run pattern. An empty pattern is no filter at all
// rather than a filter that matches nothing.
func NewTestFilter(pattern string) (*TestFilter, error) {
	if pattern == "" {
		return nil, nil
	}
	filter := &TestFilter{}
	for _, part := range strings.Split(pattern, "/") {
		compiled, err := regexp.Compile(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not a valid pattern: %w", part, err)
		}
		filter.parts = append(filter.parts, compiled)
	}
	return filter, nil
}

func (f *TestFilter) allows(depth int, name string) bool {
	if f == nil || depth >= len(f.parts) {
		return true
	}
	return f.parts[depth].MatchString(name)
}

// TestRunOptions is what the runner decides before the program starts. Both
// fields change which tests are CALLED, which is why they belong to the VM and
// not to the reporter: a test that is not selected must not run, or filtering
// would only hide output.
type TestRunOptions struct {
	Filter *TestFilter

	// Coverage asks the run to record which source lines it reached. It rides
	// here rather than in a second options struct because it is one more thing
	// the runner decides before the program starts.
	Coverage bool

	// FailFast stops calling tests once one has failed. The file's top level
	// keeps running -- it is ordinary program code and stopping it would mean
	// unwinding the run -- so what remains is skipped rather than cancelled.
	FailFast bool
}

// ConfigureTestRun installs the options and creates the ledger, so a file whose
// every test was filtered out still reports the tests it skipped rather than
// looking like a program that declared none.
func (vm *VM) ConfigureTestRun(options TestRunOptions) {
	run := vm.testLedger()
	run.options = options
}

// testScope holds the fixtures registered at one nesting level.
type testScope struct {
	before []*object.Closure
	after  []*object.Closure
}

// testRun is the ledger. It is created the first time a program calls any of
// the testing builtins, so an ordinary run pays nothing for their existence and
// `mutant test` has something to read afterwards.
type testRun struct {
	results  []*TestResult
	open     []*TestResult
	scopes   []testScope
	topLevel *TestResult

	options TestRunOptions

	// failed is sticky: once anything in the file has failed, --fail-fast skips
	// what is left.
	failed bool
}

func (vm *VM) testLedger() *testRun {
	if vm.tests == nil {
		vm.tests = &testRun{scopes: []testScope{{}}}
	}
	return vm.tests
}

// TestResults returns what the run recorded, in declaration order: a parent
// before the subtests it contains. It is nil for a program that called none of
// the testing builtins, which is how the runner tells a test file that declares
// tests from one that is simply a program.
func (vm *VM) TestResults() []*TestResult {
	if vm.tests == nil {
		return nil
	}
	return vm.tests.results
}

// current is the innermost open test, or nil when nothing is open.
func (r *testRun) current() *TestResult {
	if len(r.open) == 0 {
		return nil
	}
	return r.open[len(r.open)-1]
}

// target is where a failure goes: the innermost open test, or the file's own
// result, created on first use so a file that asserts nothing outside its tests
// does not grow an empty entry.
func (r *testRun) target() *TestResult {
	if open := r.current(); open != nil {
		return open
	}
	if r.topLevel == nil {
		r.topLevel = &TestResult{}
		r.results = append(r.results, r.topLevel)
	}
	return r.topLevel
}

func (r *testRun) push(name string) *TestResult {
	full := name
	if parent := r.current(); parent != nil {
		full = parent.Name + "/" + name
	}
	result := &TestResult{Name: full, Depth: len(r.open)}
	r.results = append(r.results, result)
	r.open = append(r.open, result)
	r.scopes = append(r.scopes, testScope{})
	return result
}

func (r *testRun) pop() {
	if len(r.open) == 0 {
		return
	}
	finished := r.open[len(r.open)-1]
	r.open = r.open[:len(r.open)-1]
	r.scopes = r.scopes[:len(r.scopes)-1]
	if parent := r.current(); parent != nil && !finished.Passed() {
		parent.FailedChildren++
	}
}

// enclosingFixtures collects the hooks that apply to a test about to run: every
// scope OUTSIDE it, setup outermost first and teardown innermost first.
//
// The test's own scope is excluded on purpose. A `before_each` written inside a
// test body applies to the subtests declared after it, which is what it reads
// like; applying it to the test it was written in would mean a fixture running
// after the body it was supposed to prepare.
func (r *testRun) enclosingFixtures() (before, after []*object.Closure) {
	outer := r.scopes
	if len(outer) > 0 {
		outer = outer[:len(outer)-1]
	}
	for _, scope := range outer {
		before = append(before, scope.before...)
	}
	for i := len(outer) - 1; i >= 0; i-- {
		after = append(after, outer[i].after...)
	}
	return before, after
}

// shouldSkip reports whether a test about to be declared must not be called:
// the filter did not select it, or --fail-fast has already seen a failure.
func (r *testRun) shouldSkip(name string) bool {
	if r.options.FailFast && r.failed {
		return true
	}
	return !r.options.Filter.allows(len(r.open), name)
}

func (r *testRun) currentScope() *testScope {
	return &r.scopes[len(r.scopes)-1]
}

// --- the builtins ---

func (vm *VM) hoTest(args []object.Object) (object.Object, error) {
	if len(args) != 2 {
		return testArgCount(builtin.BuiltinNameTest, "(name, function)", len(args)), nil
	}
	name, ok := args[0].(*object.String)
	if !ok {
		return vmErrorf("%s: first argument must be STRING, got %s", builtin.BuiltinNameTest, args[0].Type()), nil
	}
	body, errObj := testCallback(builtin.BuiltinNameTest, args[1])
	if errObj != nil {
		return errObj, nil
	}

	run := vm.testLedger()
	if run.shouldSkip(name.Value) {
		skipped := run.push(name.Value)
		skipped.Skipped = true
		run.pop()
		return global.True, nil
	}

	result := run.push(name.Value)
	before, after := run.enclosingFixtures()

	started := time.Now()
	fatal := vm.runTestBody(body, result, before, after)
	result.Elapsed = time.Since(started)
	run.pop()
	if !result.Passed() {
		run.failed = true
	}

	if fatal != nil {
		return nil, fatal
	}
	return nativeBoolToBooleanObject(result.Passed()), nil
}

// runTestBody runs the setup, the test, and the teardown. The teardown runs
// whatever the body did -- that is the guarantee it is for.
func (vm *VM) runTestBody(body *object.Closure, result *TestResult, before, after []*object.Closure) error {
	for _, hook := range before {
		if fatal := vm.runTestHook(hook, result, builtin.BuiltinNameBeforeEach); fatal != nil {
			return fatal
		}
	}

	if _, err := vm.CallClosureSync(body, nil); err != nil {
		if vm.mustNotCatch(err) {
			return err
		}
		failure := testErrorFailure(err)
		result.Err = &failure
	}

	for _, hook := range after {
		if fatal := vm.runTestHook(hook, result, builtin.BuiltinNameAfterEach); fatal != nil {
			return fatal
		}
	}
	return nil
}

// runTestHook runs one fixture. A fixture that dies is reported as a failure of
// the test it was attached to, naming which fixture it was: a teardown that
// throws is a real defect and silently dropping it would hide it.
func (vm *VM) runTestHook(hook *object.Closure, result *TestResult, kind string) error {
	if _, err := vm.CallClosureSync(hook, nil); err != nil {
		if vm.mustNotCatch(err) {
			return err
		}
		failure := testErrorFailure(err)
		failure.Message = kind + ": " + failure.Message
		result.Failures = append(result.Failures, failure)
	}
	return nil
}

// testErrorFailure turns a runtime error into a positioned failure.
//
// The VM attaches a traceback on the way out of every execution loop, including
// the one CallClosureSync re-enters, so the innermost frame is where the test
// actually died. Without it a report would name the test and not the line,
// which is the one thing the reader came for.
func testErrorFailure(err error) TestFailure {
	var runtime *RuntimeError
	if errors.As(err, &runtime) && len(runtime.Frames) > 0 {
		innermost := runtime.Frames[0]
		return TestFailure{File: innermost.File, Line: innermost.Line, Message: runtime.Err.Error()}
	}
	return TestFailure{Message: err.Error()}
}

// mustNotCatch reports whether an error that ended a test must also end the run.
//
// A test catches what the program got wrong. It does not catch the tamper
// response: swallowing that would make `mutant test` the one way to run a
// program with its own security checks disarmed. In secure mode nothing is
// caught at all, because there the checks terminate and an error reaching here
// may be one of them carrying no sentinel of its own; outside secure mode the
// probes are advisory and the three sentinels are still refused.
func (vm *VM) mustNotCatch(err error) bool {
	if vm.secureMode {
		return true
	}
	return errors.Is(err, security.ErrDebuggerDetected) ||
		errors.Is(err, security.ErrSandboxDetected) ||
		errors.Is(err, security.ErrProcessProtectionDetected)
}

func (vm *VM) hoTestFixture(kind string, args []object.Object) (object.Object, error) {
	if len(args) != 1 {
		return testArgCount(kind, "(function)", len(args)), nil
	}
	hook, errObj := testCallback(kind, args[0])
	if errObj != nil {
		return errObj, nil
	}

	scope := vm.testLedger().currentScope()
	if kind == builtin.BuiltinNameBeforeEach {
		scope.before = append(scope.before, hook)
	} else {
		scope.after = append(scope.after, hook)
	}
	return global.Null, nil
}

func (vm *VM) hoAssert(args []object.Object) (object.Object, error) {
	if len(args) < 1 || len(args) > 2 {
		return testArgCount(builtin.BuiltinNameAssert, "(condition, message?)", len(args)), nil
	}
	note, errObj := testNote(builtin.BuiltinNameAssert, args, 1)
	if errObj != nil {
		return errObj, nil
	}
	if isTruthy(args[0]) {
		return global.True, nil
	}
	return vm.recordFailure(note, "assert: %s is not true", renderTestValue(args[0])), nil
}

func (vm *VM) hoAssertEq(args []object.Object) (object.Object, error) {
	if len(args) < 2 || len(args) > 3 {
		return testArgCount(builtin.BuiltinNameAssertEq, "(got, want, message?)", len(args)), nil
	}
	note, errObj := testNote(builtin.BuiltinNameAssertEq, args, 2)
	if errObj != nil {
		return errObj, nil
	}
	if testValuesEqual(args[0], args[1]) {
		return global.True, nil
	}
	return vm.recordFailure(note, "assert_eq: got %s, want %s",
		renderTestValue(args[0]), renderTestValue(args[1])), nil
}

func (vm *VM) hoAssertNe(args []object.Object) (object.Object, error) {
	if len(args) < 2 || len(args) > 3 {
		return testArgCount(builtin.BuiltinNameAssertNe, "(got, unwanted, message?)", len(args)), nil
	}
	note, errObj := testNote(builtin.BuiltinNameAssertNe, args, 2)
	if errObj != nil {
		return errObj, nil
	}
	if !testValuesEqual(args[0], args[1]) {
		return global.True, nil
	}
	return vm.recordFailure(note, "assert_ne: both are %s", renderTestValue(args[0])), nil
}

func (vm *VM) hoAssertContains(args []object.Object) (object.Object, error) {
	if len(args) < 2 || len(args) > 3 {
		return testArgCount(builtin.BuiltinNameAssertContains, "(container, value, message?)", len(args)), nil
	}
	note, errObj := testNote(builtin.BuiltinNameAssertContains, args, 2)
	if errObj != nil {
		return errObj, nil
	}

	found, what, errObj := testContains(args[0], args[1])
	if errObj != nil {
		return errObj, nil
	}
	if found {
		return global.True, nil
	}
	return vm.recordFailure(note, "assert_contains: %s does not contain %s %s",
		renderTestValue(args[0]), what, renderTestValue(args[1])), nil
}

// testContains answers for the three containers the language has, and says
// which relation it checked so the failure message reads as the check that was
// actually made rather than a generic "does not contain".
func testContains(container, value object.Object) (found bool, relation string, errObj *object.Error) {
	switch c := container.(type) {
	case *object.String:
		text, ok := value.(*object.String)
		if !ok {
			return false, "", vmErrorf("%s: looking inside a STRING needs a STRING to look for, got %s",
				builtin.BuiltinNameAssertContains, value.Type())
		}
		return strings.Contains(c.Value, text.Value), "the substring", nil
	case *object.Array:
		for _, element := range c.Elements {
			if testValuesEqual(element, value) {
				return true, "the element", nil
			}
		}
		return false, "the element", nil
	case *object.Hash:
		key, ok := value.(object.Hashable)
		if !ok {
			return false, "", vmErrorf("%s: %s cannot be a hash key", builtin.BuiltinNameAssertContains, value.Type())
		}
		_, ok = c.Pairs[key.HashKey()]
		return ok, "the key", nil
	default:
		return false, "", vmErrorf("%s: first argument must be STRING, ARRAY or HASH, got %s",
			builtin.BuiltinNameAssertContains, container.Type())
	}
}

func (vm *VM) hoAssertErr(args []object.Object) (object.Object, error) {
	if len(args) < 1 || len(args) > 2 {
		return testArgCount(builtin.BuiltinNameAssertErr, "(value, substring?)", len(args)), nil
	}
	wanted := ""
	if len(args) == 2 {
		text, ok := args[1].(*object.String)
		if !ok {
			return vmErrorf("%s: second argument must be STRING, got %s",
				builtin.BuiltinNameAssertErr, args[1].Type()), nil
		}
		wanted = text.Value
	}

	failure, isError := args[0].(*object.Error)
	if !isError {
		return vm.recordFailure("", "assert_err: want an error, got %s %s",
			args[0].Type(), renderTestValue(args[0])), nil
	}
	if wanted != "" && !strings.Contains(failure.Message, wanted) {
		return vm.recordFailure("", "assert_err: error %q does not mention %q", failure.Message, wanted), nil
	}
	return global.True, nil
}

func (vm *VM) hoAssertOk(args []object.Object) (object.Object, error) {
	if len(args) < 1 || len(args) > 2 {
		return testArgCount(builtin.BuiltinNameAssertOk, "(value, message?)", len(args)), nil
	}
	note, errObj := testNote(builtin.BuiltinNameAssertOk, args, 1)
	if errObj != nil {
		return errObj, nil
	}
	if failure, isError := args[0].(*object.Error); isError {
		return vm.recordFailure(note, "assert_ok: %s", failure.Message), nil
	}
	return global.True, nil
}

func (vm *VM) hoFail(args []object.Object) (object.Object, error) {
	if len(args) != 1 {
		return testArgCount(builtin.BuiltinNameFail, "(message)", len(args)), nil
	}
	message, ok := args[0].(*object.String)
	if !ok {
		return vmErrorf("%s: argument must be STRING, got %s", builtin.BuiltinNameFail, args[0].Type()), nil
	}
	return vm.recordFailure("", "%s", message.Value), nil
}

// --- shared machinery ---

// recordFailure files the failure against whatever test is open and returns it
// as a value too.
//
// Both halves matter. The ledger is what `mutant test` reports; the returned
// error is what the language already means by failure, so `let ok, e =
// assert_eq(a, b)` sees it and a test file run as an ordinary program is not
// silently passing.
func (vm *VM) recordFailure(note, format string, a ...any) *object.Error {
	message := fmt.Sprintf(format, a...)
	if note != "" {
		message = note + ": " + message
	}

	run := vm.testLedger()
	file, line := vm.assertionPosition()
	target := run.target()
	target.Failures = append(target.Failures, TestFailure{File: file, Line: line, Message: message})
	run.failed = true

	return &object.Error{Message: message}
}

// assertionPosition is where the call being executed was written.
//
// A builtin pushes no frame, so the current frame is still the caller's and its
// ip is the call instruction's own offset -- the same position a traceback
// reports and the same one the debugger stops on, which is why a failed
// assertion, a breakpoint and a crash all name the same line.
func (vm *VM) assertionPosition() (string, int) {
	if vm.frameIndex <= 0 {
		return "", 0
	}
	frame := vm.currentFrame()
	if frame == nil || frame.cl == nil || frame.cl.Fn == nil || frame.ip < 0 {
		return "", 0
	}
	line, _, ok := frame.cl.Fn.LineTable.At(frame.ip)
	if !ok {
		return "", 0
	}
	if vm.bytecode == nil {
		return "", line
	}
	if path, local, ok := vm.bytecode.ModuleAt(line); ok {
		return path, local
	}
	return vm.bytecode.SourceFile, line
}

// testCallback validates the function argument the testing builtins take. All
// of them take a body of no parameters: a test is not called with anything, and
// neither is a fixture.
func testCallback(op string, arg object.Object) (*object.Closure, *object.Error) {
	cl, ok := arg.(*object.Closure)
	if !ok {
		return nil, vmErrorf("%s: the last argument must be a function, got %s", op, arg.Type())
	}
	if cl.Fn.NumParams != 0 {
		return nil, vmErrorf("%s: the function must take no parameters, got %d", op, cl.Fn.NumParams)
	}
	return cl, nil
}

// testNote reads the optional trailing message an assertion may carry.
func testNote(op string, args []object.Object, at int) (string, *object.Error) {
	if len(args) <= at {
		return "", nil
	}
	text, ok := args[at].(*object.String)
	if !ok {
		return "", vmErrorf("%s: the message must be STRING, got %s", op, args[at].Type())
	}
	return text.Value, nil
}

// testArgCount phrases an argument-count error. The word "arguments" is always
// in it, plural and unconditional, because that is what the conformance probe
// in higher_order_arity_conformance_test.go reads to tell an argument-count
// refusal from any other error.
func testArgCount(op, want string, got int) *object.Error {
	return vmErrorf("%s: wrong number of arguments: want %s, got %d", op, want, got)
}

// testValuesEqual is the comparison the assertions use: scalars by value,
// everything else by its rendered form.
//
// Rendering is not a shortcut. Hash.Inspect sorts its keys, so two hashes built
// in different orders compare equal, which is the answer a test wants and the
// one pointer identity would get wrong.
func testValuesEqual(a, b object.Object) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Type() != b.Type() {
		return false
	}
	switch left := a.(type) {
	case *object.Integer:
		return left.Value == b.(*object.Integer).Value
	case *object.Float:
		return left.Value == b.(*object.Float).Value
	case *object.String:
		return left.Value == b.(*object.String).Value
	case *object.Boolean:
		return left.Value == b.(*object.Boolean).Value
	case *object.Null:
		return true
	default:
		return a.Inspect() == b.Inspect()
	}
}

// testValueCap is how much of a value a failure message shows. A test that
// compares two large arrays has already told the reader what differs by the
// time the second line wraps; the rest is noise in a terminal.
const testValueCap = 200

func renderTestValue(value object.Object) string {
	if value == nil {
		return "null"
	}

	var rendered string
	switch concrete := value.(type) {
	case *object.Null:
		// Null inspects as the empty string, which in a failure message reads
		// as a missing word rather than as a value.
		return "null"
	case *object.String:
		// Quoted, because half of what a string assertion catches is
		// whitespace, and an unquoted "a " and "a" look identical.
		rendered = strconv.Quote(concrete.Value)
	default:
		rendered = value.Inspect()
		if rendered == "" {
			return strings.ToLower(string(value.Type()))
		}
	}

	if len(rendered) <= testValueCap {
		return rendered
	}
	return fmt.Sprintf("%s... (%d bytes)", rendered[:testValueCap], len(rendered))
}
