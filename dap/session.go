package dap

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"mutant/builtin"
	"mutant/compiler"
	"mutant/errrs"
	"mutant/generator"
	"mutant/global"
	"mutant/mutil"
	"mutant/object"
	"mutant/security"
	"mutant/vm"
)

// Options are what argv contributes to a session. Everything else arrives in
// the launch request. Nothing arrives from the environment.
type Options struct {
	// Program is the default .mut, used when the launch request names none.
	Program string

	// ModulePaths are default import roots, likewise.
	ModulePaths []string
}

// Serve runs one debug adapter session over in and out, returning when the
// client disconnects or the stream ends.
//
// Program output does not go to out. It is captured through builtin.SetOutput
// and republished as output events, which is what leaves this stream free to
// carry the protocol -- an adapter whose debuggee writes to its own transport
// corrupts every message after the first putln.
func Serve(in io.Reader, out io.Writer, options Options) error {
	s := &session{
		conn:    newConn(in, out),
		options: options,
		refs:    make(map[int]varSource),
	}
	defer s.shutdown()
	return s.loop()
}

// ListenAndServe accepts one connection on addr and serves it. It is the opt-in
// TCP form, for clients that would rather not share a process's stdio; the
// address comes from --port and never from the environment.
//
// One connection, then done: a debug adapter serves one debuggee, and a second
// client on the same port would be a second view of a session it did not start.
func ListenAndServe(addr string, options Options) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	fmt.Fprintf(os.Stderr, "[debug] waiting for a debug client on %s\n", listener.Addr())

	socket, err := listener.Accept()
	if err != nil {
		return err
	}
	defer socket.Close()

	return Serve(socket, socket, options)
}

// varSource is what one variablesReference stands for: either a set of values
// already resolved (a scope), or a handle the engine can expand (a container).
type varSource struct {
	values []vm.Variable
	handle int
}

type session struct {
	conn    *conn
	options Options

	machine  *vm.VM
	dbg      *vm.Debugger
	bytecode *compiler.ByteCode
	program  string

	restoreOutput func()

	// launched guards the one-shot transitions. A client that sends launch
	// twice, or configurationDone before launch, gets a refusal rather than a
	// second program.
	launched bool
	running  bool

	refMu   sync.Mutex
	refs    map[int]varSource
	nextRef int

	// pumpDone closes when the event pump has published the terminated event,
	// so the request loop can return once the client disconnects without
	// racing it.
	pumpDone chan struct{}

	quit bool
}

// loop reads requests until the stream ends or a disconnect is handled.
func (s *session) loop() error {
	for {
		req, err := s.conn.read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		if err := s.dispatch(req); err != nil {
			return err
		}
		if s.quit {
			return nil
		}
	}
}

func (s *session) dispatch(req *request) error {
	switch req.Command {
	case "initialize":
		return s.onInitialize(req)
	case "launch":
		return s.onLaunch(req)
	case "attach":
		// The adapter is the debuggee. There is no separate process to attach
		// to, and attaching an OS debugger to a running mutant is what the
		// anti-reversing probes exist to stop -- see decision 1 in
		// plans/T1_DEBUGGER.md.
		return s.fail(req, "mutant debugs by launching the program, not by attaching to one. "+
			"Use a launch configuration naming the .mut file.")
	case "setBreakpoints":
		return s.onSetBreakpoints(req)
	case "breakpointLocations":
		return s.onBreakpointLocations(req)
	case "setExceptionBreakpoints":
		// Nothing to set: a mutant runtime error ends the program, and there is
		// no throw to break on. Answered successfully because a client sends it
		// unconditionally and a refusal would read as a broken adapter.
		return s.ok(req, map[string]any{"breakpoints": []any{}})
	case "configurationDone":
		return s.onConfigurationDone(req)
	case "threads":
		return s.ok(req, map[string]any{
			"threads": []thread{{ID: mainThreadID, Name: mainThreadName}},
		})
	case "stackTrace":
		return s.onStackTrace(req)
	case "scopes":
		return s.onScopes(req)
	case "variables":
		return s.onVariables(req)
	case "continue":
		return s.onResume(req, func() error { return s.dbg.Continue() },
			map[string]any{"allThreadsContinued": true})
	case "next":
		return s.onResume(req, func() error { return s.dbg.Next() }, nil)
	case "stepIn":
		return s.onResume(req, func() error { return s.dbg.StepIn() }, nil)
	case "stepOut":
		return s.onResume(req, func() error { return s.dbg.StepOut() }, nil)
	case "pause":
		return s.onPause(req)
	case "evaluate":
		return s.onEvaluate(req)
	case "disconnect", "terminate":
		return s.onDisconnect(req)
	default:
		return s.fail(req, fmt.Sprintf("this adapter does not implement %q", req.Command))
	}
}

// ------------------------------------------------------------------ replies

func (s *session) ok(req *request, body any) error {
	return s.conn.send(&response{
		Type: "response", RequestSeq: req.Seq, Success: true, Command: req.Command, Body: body,
	})
}

func (s *session) fail(req *request, message string) error {
	return s.conn.send(&response{
		Type: "response", RequestSeq: req.Seq, Success: false, Command: req.Command, Message: message,
	})
}

func (s *session) event(name string, body any) error {
	return s.conn.send(&event{Type: "event", Event: name, Body: body})
}

// --------------------------------------------------------------- lifecycle

func (s *session) onInitialize(req *request) error {
	return s.ok(req, capabilities{
		SupportsConfigurationDoneRequest:   true,
		SupportsTerminateRequest:           true,
		SupportsBreakpointLocationsRequest: true,
		SupportsHitConditionalBreakpoints:  true,
	})
}

// onLaunch compiles the program and attaches a debugger, but does not start it.
//
// The initialized event is sent *after* that work, not after initialize, which
// is what serialises the handshake: a client sends its breakpoints when it sees
// initialized, and breakpoints can only be bound once there is a program to
// bind them against.
func (s *session) onLaunch(req *request) error {
	if s.launched {
		return s.fail(req, "this session already has a program; start a new one to debug another")
	}

	var args launchArguments
	if len(req.Arguments) > 0 {
		if err := json.Unmarshal(req.Arguments, &args); err != nil {
			return s.fail(req, fmt.Sprintf("the launch arguments could not be read: %v", err))
		}
	}

	program := args.Program
	if program == "" {
		program = s.options.Program
	}
	if program == "" {
		return s.fail(req, "no program to debug: name a .mut file in the launch configuration")
	}

	absolute, err := filepath.Abs(program)
	if err != nil {
		return s.fail(req, fmt.Sprintf("%s: %v", program, err))
	}

	modulePaths := args.ModulePaths
	if len(modulePaths) == 0 {
		modulePaths = s.options.ModulePaths
	}

	bytecode, compileErr, errType, details := generator.CompileForDebug(absolute, modulePaths)
	if compileErr != nil {
		return s.fail(req, compileFailureMessage(compileErr, errType, details))
	}

	s.program = absolute
	s.bytecode = bytecode

	// Sealed exactly as an artifact is, so the program being stepped is the
	// program that runs: values live encrypted on the stack, and a debugger
	// reading them goes through the same decryption every other reader does.
	password := fmt.Sprint(security.DerivePasswordFromInstructions(bytecode.Instructions))
	sealed := mutil.EncryptByteCode(bytecode, password)

	globals := make([]object.Object, global.GlobalSize)
	s.machine = vm.NewWithPasswordAndGlobalStore(sealed, password, globals)

	s.dbg, err = vm.NewDebugger(s.machine, vm.DebugOptions{StopOnEntry: args.StopOnEntry && !args.NoDebug})
	if err != nil {
		return s.fail(req, err.Error())
	}

	// Program output becomes output events from here on, which is what keeps it
	// off the transport.
	s.restoreOutput = builtin.SetOutput(&eventWriter{session: s, category: "stdout"})

	s.launched = true
	if err := s.ok(req, map[string]any{}); err != nil {
		return err
	}
	return s.event("initialized", map[string]any{})
}

// compileFailureMessage renders a failed compile the way the CLI would, so the
// same mistake reads the same whether it was found by `mutant run` or by the
// editor.
func compileFailureMessage(err error, errType errrs.ErrorType, details []string) string {
	if errType == errrs.PARSER_ERROR && len(details) > 0 {
		return "the program has parse errors:\n" + strings.Join(details, "\n")
	}
	return err.Error()
}

func (s *session) onConfigurationDone(req *request) error {
	if !s.launched {
		return s.fail(req, "there is no program to start: send a launch request first")
	}
	if s.running {
		return s.fail(req, "the program is already running")
	}

	if err := s.ok(req, map[string]any{}); err != nil {
		return err
	}

	s.running = true
	s.pumpDone = make(chan struct{})
	go s.pump()
	s.dbg.Run()
	return nil
}

// pump republishes the engine's halts as protocol events.
func (s *session) pump() {
	defer close(s.pumpDone)

	for stop := range s.dbg.Events() {
		if stop.Reason == vm.StopExited {
			s.publishExit(stop.Err)
			return
		}

		s.resetRefs()

		body := stoppedBody{
			Reason:            stoppedReason(stop.Reason),
			ThreadID:          mainThreadID,
			AllThreadsStopped: true,
		}
		if stop.Reason == vm.StopBreakpoint && stop.Breakpoint.ID != 0 {
			body.HitBreakpointIDs = []int{stop.Breakpoint.ID}
		}
		_ = s.event("stopped", body)
	}
}

// publishExit reports how the run ended: the program's own last value, then any
// failure, then the exit.
func (s *session) publishExit(runErr error) {
	code := 0

	if runErr == nil {
		s.publishResultValue()
	} else {
		code = 1
		text := runErr.Error()
		var runtimeErr *vm.RuntimeError
		if errors.As(runErr, &runtimeErr) {
			if traceback := runtimeErr.Traceback(); traceback != "" {
				text += "\n" + traceback
			}
		}
		_ = s.event("output", outputBody{Category: "stderr", Output: text + "\n"})
	}

	// After this the stack is gone, which is why it runs once the last value
	// has been read and never before.
	if s.machine != nil {
		builtin.WaitForTasks()
		s.machine.CleanupSensitiveData(true)
	}

	_ = s.event("exited", exitedBody{ExitCode: code})
	_ = s.event("terminated", map[string]any{})
}

// publishResultValue prints the program's value the way `mutant run` does, so a
// session that steps a program to the end shows what running it would have
// shown.
func (s *session) publishResultValue() {
	last := s.machine.LastPoppedStackElement()
	if last == nil {
		return
	}
	if multi, ok := last.(*object.MultiValue); ok && multi.IsVoid() {
		return
	}
	_ = s.event("output", outputBody{Category: "stdout", Output: last.Inspect() + "\n"})
}

func stoppedReason(reason vm.StopReason) string {
	switch reason {
	case vm.StopEntry:
		return "entry"
	case vm.StopBreakpoint:
		return "breakpoint"
	case vm.StopStep:
		return "step"
	case vm.StopPause:
		return "pause"
	}
	return string(reason)
}

func (s *session) onDisconnect(req *request) error {
	if s.dbg != nil {
		s.dbg.Terminate()
	}
	s.quit = true
	return s.ok(req, map[string]any{})
}

// shutdown releases what the session took from the process. Program output is
// restored first, because leaving it pointed at a closed transport would make
// the next program in the same process write into nothing.
func (s *session) shutdown() {
	if s.restoreOutput != nil {
		s.restoreOutput()
		s.restoreOutput = nil
	}
	if s.dbg != nil {
		s.dbg.Terminate()
	}
	if s.pumpDone != nil {
		<-s.pumpDone
	}
}

// ------------------------------------------------------------- breakpoints

func (s *session) onSetBreakpoints(req *request) error {
	if s.dbg == nil {
		return s.fail(req, "there is no program yet: send a launch request first")
	}

	var args setBreakpointsArguments
	if err := json.Unmarshal(req.Arguments, &args); err != nil {
		return s.fail(req, fmt.Sprintf("the breakpoints could not be read: %v", err))
	}

	requested := args.Breakpoints
	if len(requested) == 0 && len(args.Lines) > 0 {
		requested = make([]sourceBreakpoint, 0, len(args.Lines))
		for _, line := range args.Lines {
			requested = append(requested, sourceBreakpoint{Line: line})
		}
	}

	specs := make([]vm.BreakpointSpec, 0, len(requested))
	notes := make([]string, len(requested))
	for i, want := range requested {
		spec := vm.BreakpointSpec{Line: want.Line}
		if want.HitCondition != "" {
			skip, ok := parseHitCondition(want.HitCondition)
			if !ok {
				notes[i] = fmt.Sprintf("the hit condition %q was not understood and is ignored; "+
					"write a count such as 5, or >5", want.HitCondition)
			}
			spec.SkipHits = skip
		}
		if want.Condition != "" {
			// Kept armed rather than dropped. A breakpoint that silently never
			// fires is the worse of the two failures, and the note says exactly
			// what is happening.
			notes[i] = appendNote(notes[i], "conditions are not supported: this breakpoint stops every time. "+
				"Evaluating a condition needs the compiler's scope for this frame, which a compiled program does not carry")
		}
		if want.LogMessage != "" {
			notes[i] = appendNote(notes[i], "log points are not supported: this breakpoint stops instead of logging")
		}
		specs = append(specs, spec)
	}

	bound, err := s.dbg.SetBreakpoints(s.moduleSpelling(args.Source.Path), specs)
	if err != nil {
		return s.fail(req, err.Error())
	}

	out := make([]breakpoint, 0, len(bound))
	for i, bp := range bound {
		rendered := breakpoint{
			ID:       bp.ID,
			Verified: bp.Verified,
			Line:     bp.Line,
			Message:  bp.Message,
			Source:   &source{Name: filepath.Base(args.Source.Path), Path: args.Source.Path},
		}
		if i < len(notes) {
			rendered.Message = appendNote(rendered.Message, notes[i])
		}
		out = append(out, rendered)
	}
	return s.ok(req, map[string]any{"breakpoints": out})
}

func appendNote(existing, note string) string {
	switch {
	case note == "":
		return existing
	case existing == "":
		return note
	}
	return existing + "; " + note
}

// parseHitCondition reads the counts DAP clients actually send. A bare count
// means "stop on the Nth arrival"; the forms with an operator mean what they
// say. Anything else is refused rather than guessed at, and the caller says so
// in the breakpoint's message.
func parseHitCondition(condition string) (skip int, ok bool) {
	text := strings.TrimSpace(condition)

	switch {
	case strings.HasPrefix(text, ">="):
		text = strings.TrimSpace(text[2:])
	case strings.HasPrefix(text, "=="):
		text = strings.TrimSpace(text[2:])
	case strings.HasPrefix(text, "="):
		text = strings.TrimSpace(text[1:])
	case strings.HasPrefix(text, ">"):
		// "> 5" is the sixth arrival onwards.
		count, err := strconv.Atoi(strings.TrimSpace(text[1:]))
		if err != nil || count < 0 {
			return 0, false
		}
		return count, true
	}

	count, err := strconv.Atoi(text)
	if err != nil || count < 1 {
		return 0, false
	}
	return count - 1, true
}

func (s *session) onBreakpointLocations(req *request) error {
	if s.dbg == nil {
		return s.fail(req, "there is no program yet: send a launch request first")
	}

	var args breakpointLocationsArguments
	if err := json.Unmarshal(req.Arguments, &args); err != nil {
		return s.fail(req, fmt.Sprintf("the request could not be read: %v", err))
	}

	last := args.EndLine
	if last < args.Line {
		last = args.Line
	}

	out := make([]breakpointLocation, 0, 4)
	for _, line := range s.dbg.BreakpointLines(s.moduleSpelling(args.Source.Path)) {
		if line >= args.Line && line <= last {
			out = append(out, breakpointLocation{Line: line})
		}
	}
	return s.ok(req, map[string]any{"breakpoints": out})
}

// moduleSpelling turns the path an editor sent into the spelling the program's
// module spans use.
//
// The two differ routinely: an editor sends the absolute path of the file the
// user opened, and a span carries the display path the module walker recorded,
// which is relative to the working directory whenever that does not climb out
// of it. Comparing absolute forms is what makes them meet. Falling through with
// the editor's own path is not a failure -- the engine has its own matching
// rule -- it just gives that rule a better starting point.
func (s *session) moduleSpelling(path string) string {
	if path == "" || s.bytecode == nil {
		return path
	}

	want, err := filepath.Abs(path)
	if err != nil {
		return path
	}

	for _, span := range s.bytecode.ModuleSpans {
		spanAbs, err := filepath.Abs(span.Path)
		if err != nil {
			continue
		}
		if samePath(spanAbs, want) {
			return span.Path
		}
	}
	return path
}

// samePath compares two absolute paths, case-insensitively where the platform's
// file names are. Getting this wrong on Windows means every breakpoint an
// editor sets with a lower-case drive letter misses.
func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// ------------------------------------------------------------------- state

func (s *session) onStackTrace(req *request) error {
	if s.dbg == nil {
		return s.fail(req, "there is no program yet")
	}

	var args stackTraceArguments
	_ = json.Unmarshal(req.Arguments, &args)

	frames, err := s.dbg.Frames()
	if err != nil {
		return s.fail(req, err.Error())
	}

	out := make([]stackFrame, 0, len(frames))
	for i, frame := range frames {
		out = append(out, stackFrame{
			ID:        i + 1,
			Name:      frame.Signature(),
			Source:    s.sourceFor(frame.File),
			Line:      frame.Line,
			Column:    frame.Column,
			EndLine:   frame.EndLine,
			EndColumn: frame.EndColumn,
		})
	}

	// A client may ask for a window of the stack. Total stays the full depth so
	// it can page through the rest.
	total := len(out)
	if args.StartFrame > 0 {
		if args.StartFrame >= len(out) {
			out = nil
		} else {
			out = out[args.StartFrame:]
		}
	}
	if args.Levels > 0 && args.Levels < len(out) {
		out = out[:args.Levels]
	}

	return s.ok(req, map[string]any{"stackFrames": out, "totalFrames": total})
}

// sourceFor renders a frame's file for the editor, as an absolute path.
//
// The path in a frame is the module walker's display spelling, which is
// relative to the working directory the compile ran in -- and this process is
// that compile, so resolving it here resolves it against the right directory.
func (s *session) sourceFor(path string) *source {
	if path == "" {
		return nil
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		absolute = path
	}
	return &source{Name: filepath.Base(path), Path: absolute}
}

func (s *session) onScopes(req *request) error {
	if s.dbg == nil {
		return s.fail(req, "there is no program yet")
	}

	var args scopesArguments
	if err := json.Unmarshal(req.Arguments, &args); err != nil {
		return s.fail(req, fmt.Sprintf("the request could not be read: %v", err))
	}

	frame := args.FrameID - 1
	if frame < 0 {
		frame = 0
	}

	groups, err := s.dbg.Scopes(frame)
	if err != nil {
		return s.fail(req, err.Error())
	}

	out := make([]scope, 0, len(groups))
	for _, group := range groups {
		out = append(out, scope{
			Name:               group.Name,
			PresentationHint:   scopeHint(group.Name),
			VariablesReference: s.holdValues(group.Variables),
		})
	}
	return s.ok(req, map[string]any{"scopes": out})
}

func scopeHint(name string) string {
	switch name {
	case "Arguments":
		return "arguments"
	case "Locals":
		return "locals"
	}
	return ""
}

func (s *session) onVariables(req *request) error {
	if s.dbg == nil {
		return s.fail(req, "there is no program yet")
	}

	var args variablesArguments
	if err := json.Unmarshal(req.Arguments, &args); err != nil {
		return s.fail(req, fmt.Sprintf("the request could not be read: %v", err))
	}

	held, ok := s.lookupRef(args.VariablesReference)
	if !ok {
		return s.fail(req, fmt.Sprintf("reference %d belongs to an earlier stop and no longer resolves",
			args.VariablesReference))
	}

	values := held.values
	if values == nil && held.handle > 0 {
		children, err := s.dbg.Children(held.handle)
		if err != nil {
			return s.fail(req, err.Error())
		}
		values = children
	}

	out := make([]variable, 0, len(values))
	for _, value := range values {
		out = append(out, variable{
			Name:               value.Name,
			Value:              value.Value,
			Type:               value.Type,
			VariablesReference: s.holdHandle(value.Ref),
		})
	}
	return s.ok(req, map[string]any{"variables": out})
}

func (s *session) onEvaluate(req *request) error {
	if s.dbg == nil {
		return s.fail(req, "there is no program yet")
	}

	var args evaluateArguments
	if err := json.Unmarshal(req.Arguments, &args); err != nil {
		return s.fail(req, fmt.Sprintf("the request could not be read: %v", err))
	}

	frame := args.FrameID - 1
	if frame < 0 {
		frame = 0
	}

	value, err := s.dbg.Evaluate(frame, args.Expression)
	if err != nil {
		return s.fail(req, err.Error())
	}

	return s.ok(req, map[string]any{
		"result":             value.Value,
		"type":               value.Type,
		"variablesReference": s.holdHandle(value.Ref),
	})
}

// ----------------------------------------------------------------- control

func (s *session) onResume(req *request, resume func() error, body map[string]any) error {
	if s.dbg == nil {
		return s.fail(req, "there is no program yet")
	}
	if err := resume(); err != nil {
		return s.fail(req, err.Error())
	}
	if body == nil {
		body = map[string]any{}
	}
	return s.ok(req, body)
}

func (s *session) onPause(req *request) error {
	if s.dbg == nil {
		return s.fail(req, "there is no program yet")
	}
	s.dbg.Pause()
	return s.ok(req, map[string]any{})
}

// ------------------------------------------------------------- references

// holdValues files a resolved set of values under a fresh reference.
func (s *session) holdValues(values []vm.Variable) int {
	if len(values) == 0 {
		return 0
	}

	s.refMu.Lock()
	defer s.refMu.Unlock()

	s.nextRef++
	s.refs[s.nextRef] = varSource{values: values}
	return s.nextRef
}

// holdHandle files an engine handle under a fresh reference. A zero handle is a
// leaf, and DAP spells "no children" as reference zero.
func (s *session) holdHandle(handle int) int {
	if handle == 0 {
		return 0
	}

	s.refMu.Lock()
	defer s.refMu.Unlock()

	s.nextRef++
	s.refs[s.nextRef] = varSource{handle: handle}
	return s.nextRef
}

func (s *session) lookupRef(ref int) (varSource, bool) {
	s.refMu.Lock()
	defer s.refMu.Unlock()

	held, ok := s.refs[ref]
	return held, ok
}

// resetRefs drops every reference at each stop, because a reference into a
// value the program has since reassigned points at the wrong thing. Numbering
// carries on rather than restarting, so a stale reference is refused rather
// than quietly answering with whatever now holds that number.
func (s *session) resetRefs() {
	s.refMu.Lock()
	defer s.refMu.Unlock()

	s.refs = make(map[int]varSource, 8)
}

// eventWriter turns a write by the program into an output event.
type eventWriter struct {
	session  *session
	category string
}

func (w *eventWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	_ = w.session.event("output", outputBody{Category: w.category, Output: string(p)})
	return len(p), nil
}
