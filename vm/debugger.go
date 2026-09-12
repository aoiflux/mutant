package vm

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"mutant/code"
	"mutant/object"
)

// A Debugger drives one VM one instruction at a time: breakpoints, stepping,
// and reading back the frames, scopes and values the program is holding.
//
// It is deliberately headless. Nothing here knows about the Debug Adapter
// Protocol, and `mutant debug` is a translation layer over these calls, so a
// protocol bug and an engine bug are never the same bug and a second front end
// costs nothing.
//
// # The shape of a session
//
// The VM runs on its own goroutine, started by Run. Whenever it stops -- an
// entry stop, a breakpoint, a completed step, a pause request -- it publishes a
// Stop on Events and then blocks until the consumer answers with Continue,
// Next, StepIn, StepOut or Terminate. Reading state is only meaningful in that
// window, and every reader says so: a call made while the program is running
// returns ErrNotStopped rather than racing the executor for the stack.
//
// The last event of a session is always one with reason StopExited, carrying
// the run's outcome, after which Events is closed.
//
// # What it cannot see
//
//   - A stripped artifact. NewDebugger refuses one: with no line tables there
//     is no position to stop at and nothing to name a slot with, and rendering
//     the values in a program that left the machine is the disclosure
//     frameArguments already declines to make.
//   - Work running on a sibling VM. spawn and pmap build their own VMs, which
//     have no debugger attached, so a callback handed to them runs at full
//     speed and is not stepped. A closure called back through a builtin on
//     *this* VM -- map, filter, with_resource -- re-enters the same executor
//     and is stepped normally.
type Debugger struct {
	vm *VM

	// mainFn is frame 0's function, captured at attach. It is the program's own
	// instruction stream wearing a frame's clothes, and it is not reachable
	// through the constant pool, so a breakpoint on a top-level line would
	// otherwise have nowhere to bind.
	mainFn *object.CompiledFunction

	options DebugOptions

	events chan Stop
	resume chan command

	// done is closed by Terminate. Every blocking send and receive in the hook
	// selects on it, so a consumer that walks away cannot strand the executor
	// goroutine on a channel nobody will ever read.
	done     chan struct{}
	doneOnce sync.Once

	started atomic.Bool
	exited  atomic.Bool

	// stopped is true exactly while the executor is parked in the hook, which
	// is the only time reading VM state is safe. It is set before the Stop is
	// published and cleared after the answer arrives, so a consumer that reads
	// the moment it receives an event always finds it set.
	stopped atomic.Bool

	// pauseRequested is how a pause reaches a running executor: the hook checks
	// one atomic per instruction rather than taking a lock.
	pauseRequested atomic.Bool

	// breaks is swapped wholesale rather than edited, so the hook reads it with
	// no lock at all while SetBreakpoints runs on another goroutine.
	breaks atomic.Pointer[breakSet]

	// entryDone records that the entry stop has been taken, so it happens once
	// rather than on the first instruction of every frame.
	entryDone bool

	// The stepping state is written by the executor goroutine at each stop and
	// read by it alone. A command from the consumer arrives through resume,
	// which is what publishes it.
	mode      command
	baseDepth int
	baseLine  int
	baseFn    *object.CompiledFunction

	// sites indexes every line that has code, across the program's stream and
	// every compiled function's, to the instruction that line begins at. Built
	// once at attach: the streams are fixed for the life of a program.
	sites     map[int][]breakSite
	codeLines []int

	// handles is the expansion table behind Variable.Ref. It is cleared at
	// every resume because a reference into a value that has since been
	// reassigned is a reference to the wrong value.
	handleMu   sync.Mutex
	handles    map[int]object.Object
	nextHandle int

	nextBreakpointID int
}

// DebugOptions are the session's settings. They arrive from argv or from the
// launch request, never from the environment; see docs/CONFIGURATION_POLICY.md.
type DebugOptions struct {
	// StopOnEntry parks the program before its first instruction, which is what
	// an editor wants when the user starts a session with no breakpoints set.
	StopOnEntry bool
}

// StopReason says why the program is parked.
type StopReason string

const (
	// StopEntry is the halt before the first instruction, taken when
	// DebugOptions.StopOnEntry is set.
	StopEntry StopReason = "entry"
	// StopBreakpoint is a halt at a bound breakpoint.
	StopBreakpoint StopReason = "breakpoint"
	// StopStep is a halt because a step finished.
	StopStep StopReason = "step"
	// StopPause is a halt because the consumer asked for one.
	StopPause StopReason = "pause"
	// StopExited is the final event: the program is over, and Err says how.
	StopExited StopReason = "exited"
)

// Stop is one published halt.
type Stop struct {
	Reason StopReason

	// Breakpoint is the breakpoint that was hit, set only for StopBreakpoint.
	Breakpoint Breakpoint

	// Err is the run's outcome, set only for StopExited. A program that ran to
	// completion reports nil; one that failed reports the VM's error, traceback
	// and all.
	Err error
}

// BreakpointSpec is one requested breakpoint.
type BreakpointSpec struct {
	// Line is the line in File the user marked, 1-based.
	Line int

	// SkipHits passes over the first SkipHits arrivals before stopping. It is
	// what a hit condition compiles to, and it is deliberately the only
	// condition this engine takes: a general condition is an expression, and
	// evaluating one in a frame needs a symbol table the artifact does not
	// carry. See the deferral in plans/T1_DEBUGGER.md.
	SkipHits int
}

// Breakpoint is a requested breakpoint together with what became of it.
type Breakpoint struct {
	ID int

	// File and Line are what was asked for. Bound is the line it landed on,
	// which differs when the requested line emitted no instruction of its own.
	File  string
	Line  int
	Bound int

	// Verified is false when the line could not be bound at all, and Message
	// then says why. An unverified breakpoint is reported rather than dropped:
	// an editor that shows a solid marker for a breakpoint that can never be
	// hit is lying to the person who set it.
	Verified bool
	Message  string

	// SkipHits is the spec's, carried through so a consumer can render it.
	SkipHits int

	hits *atomic.Int64
}

// Hits is how many times execution has reached this breakpoint, counting the
// arrivals skipped by SkipHits.
func (b Breakpoint) Hits() int {
	if b.hits == nil {
		return 0
	}
	return int(b.hits.Load())
}

// Scope is one group of values shown against a frame.
type Scope struct {
	Name      string
	Variables []Variable
}

// Variable is one named value.
type Variable struct {
	Name string

	// Type is the runtime type name, and Value its rendering, capped. A value
	// too large to render in full is truncated rather than summarised, so what
	// is shown is always a prefix of the truth.
	Type  string
	Value string

	// Ref is non-zero when the value has children to expand, and is the handle
	// to pass to Children. Handles are invalidated at every resume.
	Ref int
}

type command int

const (
	cmdContinue command = iota
	cmdNext
	cmdStepIn
	cmdStepOut
	cmdTerminate
)

// breakSite is one instruction a breakpoint is bound to. A line can own several
// -- `let f = fn(x) { x + 1 };` puts code from one line in two streams -- and
// all of them are armed, because either may be the one that runs.
type breakSite struct {
	fn *object.CompiledFunction
	ip int
}

// breakSet is an immutable snapshot of the armed breakpoints, swapped in one
// atomic store so the hook never takes a lock.
type breakSet struct {
	// byFile keeps the requested breakpoints per source file, because DAP's
	// setBreakpoints replaces one file's set and leaves the others alone.
	byFile map[string][]Breakpoint

	// sites is what the hook consults: every armed instruction, to the
	// breakpoint that armed it.
	sites map[breakSite]Breakpoint
}

// Errors a caller is expected to handle rather than merely report.
var (
	// ErrNotStopped is returned by every reader called while the program is
	// running. Reading the stack from another goroutine mid-instruction would
	// be a data race, and a wrong answer from a debugger is worse than none.
	ErrNotStopped = errors.New("the program is running: state can only be read while it is stopped")

	// ErrTerminated unwinds the executor when a session is torn down.
	ErrTerminated = errors.New("debug session terminated")

	// ErrNoDebugInfo is why a stripped artifact cannot be debugged.
	ErrNoDebugInfo = errors.New("this program carries no source positions: it was built for release, and there is nothing to step through")
)

const (
	// maxDebugValue caps one rendered value. Longer than a traceback's, which
	// is a one-line summary; short enough that a hash of ten thousand keys does
	// not arrive as one string.
	maxDebugValue = 256

	// maxDebugChildren caps one expansion. The overflow is reported as an extra
	// entry rather than silently dropped.
	maxDebugChildren = 200
)

// NewDebugger attaches to vm, which must not have been run yet.
//
// It refuses a program with no line tables. That is a release artifact, and the
// refusal is two things at once: there is genuinely nothing to step through,
// and the values on that program's stack are not this machine's to render --
// the same line frameArguments draws.
func NewDebugger(vm *VM, options DebugOptions) (*Debugger, error) {
	if vm == nil {
		return nil, errors.New("no VM to debug")
	}
	if vm.debug != nil {
		return nil, errors.New("this VM already has a debugger attached")
	}
	if vm.frameIndex < 1 || vm.frames[0] == nil || vm.frames[0].cl == nil || vm.frames[0].cl.Fn == nil {
		return nil, errors.New("this VM has no main frame to debug")
	}
	if vm.bytecode == nil || vm.bytecode.LineTable.Empty() {
		return nil, ErrNoDebugInfo
	}

	d := &Debugger{
		vm:      vm,
		mainFn:  vm.frames[0].cl.Fn,
		options: options,
		events:  make(chan Stop),
		resume:  make(chan command),
		done:    make(chan struct{}),
		handles: make(map[int]object.Object),
	}
	d.buildSites()
	vm.debug = d
	return d, nil
}

// buildSites indexes every stream the program can execute: its own, and every
// compiled function in the constant pool. The main stream is taken from frame 0
// rather than from the bytecode because that is the CompiledFunction the frames
// will actually carry, and breakpoints are keyed by that identity.
func (d *Debugger) buildSites() {
	d.sites = make(map[int][]breakSite, 64)

	streams := make([]*object.CompiledFunction, 0, len(d.vm.constants)+1)
	streams = append(streams, d.mainFn)
	for _, constant := range d.vm.constants {
		if fn, ok := constant.(*object.CompiledFunction); ok && fn != nil {
			streams = append(streams, fn)
		}
	}

	for _, fn := range streams {
		index := code.BuildLineIndex(fn.LineTable)
		for _, line := range index.Lines() {
			ip, _, ok := index.At(line)
			if !ok {
				continue
			}
			d.sites[line] = append(d.sites[line], breakSite{fn: fn, ip: ip})
		}
	}

	d.codeLines = make([]int, 0, len(d.sites))
	for line := range d.sites {
		d.codeLines = append(d.codeLines, line)
	}
	sort.Ints(d.codeLines)
}

// Events is the channel every halt arrives on. It is closed after the
// StopExited event, so a consumer can range over it.
func (d *Debugger) Events() <-chan Stop { return d.events }

// Run starts the program on its own goroutine and returns immediately. The
// caller drives the session through Events and the stepping calls.
func (d *Debugger) Run() {
	if !d.started.CompareAndSwap(false, true) {
		return
	}

	go func() {
		err := d.vm.Run()

		// ErrTerminated is this package's own unwinding signal, not a failure
		// of the program, and it reaches here wrapped in whatever the executor
		// wrapped it in. Reporting it as the run's outcome would make an
		// ordinary disconnect look like a crash.
		if errors.Is(err, ErrTerminated) {
			err = nil
		}

		d.exited.Store(true)
		d.stopped.Store(false)

		select {
		case d.events <- Stop{Reason: StopExited, Err: err}:
		case <-d.done:
		}
		close(d.events)
	}()
}

// step is the hook the executor calls before each instruction, with the frame's
// ip already advanced to the instruction about to run. Returning an error
// unwinds the run.
//
// The order of the three tests is the order of their authority. A terminate
// outranks everything. A pause the consumer asked for outranks a breakpoint,
// because a consumer that asked to stop should not be told it stopped for some
// other reason. A breakpoint outranks a step in progress, because the
// breakpoint is the more specific thing the user asked for.
func (d *Debugger) step() error {
	select {
	case <-d.done:
		return ErrTerminated
	default:
	}

	if d.options.StopOnEntry && !d.entryDone {
		d.entryDone = true
		return d.halt(Stop{Reason: StopEntry})
	}
	d.entryDone = true

	if d.pauseRequested.CompareAndSwap(true, false) {
		return d.halt(Stop{Reason: StopPause})
	}

	frame := d.vm.currentFrame()
	if frame == nil || frame.cl == nil || frame.cl.Fn == nil {
		return nil
	}

	if breaks := d.breaks.Load(); breaks != nil && len(breaks.sites) > 0 {
		if bp, ok := breaks.sites[breakSite{fn: frame.cl.Fn, ip: frame.ip}]; ok {
			hits := int(bp.hits.Add(1))
			if hits > bp.SkipHits {
				return d.halt(Stop{Reason: StopBreakpoint, Breakpoint: bp})
			}
		}
	}

	if d.mode != cmdContinue && d.stepIsDone(frame) {
		return d.halt(Stop{Reason: StopStep})
	}
	return nil
}

// stepIsDone reports whether the step in progress has arrived somewhere worth
// showing.
//
// Every answer is gated on the instruction having a position. Stepping to an
// instruction the compiler synthesised on its own behalf would park the editor
// on no line at all, which reads as a hung debugger.
func (d *Debugger) stepIsDone(frame *Frame) bool {
	depth := d.vm.frameIndex

	// Leaving the frame the step started in ends every kind of step: there is
	// no "rest of this line" left to run.
	if depth < d.baseDepth {
		return d.positionOf(frame) > 0
	}

	line := d.positionOf(frame)
	if line <= 0 {
		return false
	}

	switch d.mode {
	case cmdStepOut:
		// Already handled by the depth test above; deeper or level is not out.
		return false
	case cmdNext:
		// A call made by this line runs to completion without stopping, which
		// is the whole of step-over.
		return depth == d.baseDepth && (frame.cl.Fn != d.baseFn || line != d.baseLine)
	case cmdStepIn:
		return depth != d.baseDepth || frame.cl.Fn != d.baseFn || line != d.baseLine
	}
	return false
}

// positionOf is the line of the linked blob the frame's current instruction
// came from, or 0 when the instruction carries no position.
func (d *Debugger) positionOf(frame *Frame) int {
	if frame == nil || frame.cl == nil || frame.cl.Fn == nil || frame.ip < 0 {
		return 0
	}
	line, _, ok := frame.cl.Fn.LineTable.At(frame.ip)
	if !ok {
		return 0
	}
	return line
}

// halt publishes the stop and parks until the consumer answers.
func (d *Debugger) halt(stop Stop) error {
	d.resetHandles()
	d.stopped.Store(true)

	select {
	case d.events <- stop:
	case <-d.done:
		d.stopped.Store(false)
		return ErrTerminated
	}

	var next command
	select {
	case next = <-d.resume:
	case <-d.done:
		d.stopped.Store(false)
		return ErrTerminated
	}

	d.stopped.Store(false)

	if next == cmdTerminate {
		return ErrTerminated
	}

	// The step that was just asked for is measured from here.
	frame := d.vm.currentFrame()
	d.mode = next
	d.baseDepth = d.vm.frameIndex
	d.baseFn = nil
	d.baseLine = 0
	if frame != nil && frame.cl != nil {
		d.baseFn = frame.cl.Fn
		d.baseLine = d.positionOf(frame)
	}
	return nil
}

// Continue resumes the program until the next breakpoint, pause or exit.
func (d *Debugger) Continue() error { return d.send(cmdContinue) }

// Next runs to the next line of the current frame, stepping over any call the
// current line makes.
func (d *Debugger) Next() error { return d.send(cmdNext) }

// StepIn runs to the next line anywhere, which is the first line of a callee
// when the current line calls one.
func (d *Debugger) StepIn() error { return d.send(cmdStepIn) }

// StepOut runs until the current frame returns.
func (d *Debugger) StepOut() error { return d.send(cmdStepOut) }

func (d *Debugger) send(cmd command) error {
	if d.exited.Load() {
		return errors.New("the program has already finished")
	}
	if !d.stopped.Load() {
		return ErrNotStopped
	}

	select {
	case d.resume <- cmd:
		return nil
	case <-d.done:
		return ErrTerminated
	}
}

// Pause asks the program to stop at the next instruction it executes. It is the
// one control that is meaningful while the program is running, and it returns
// as soon as the request is recorded rather than waiting for the halt -- the
// halt arrives on Events like any other.
func (d *Debugger) Pause() {
	if d.exited.Load() {
		return
	}
	d.pauseRequested.Store(true)
}

// Terminate ends the session. It unblocks a parked executor and unwinds a
// running one, and it is safe to call more than once and from any goroutine.
func (d *Debugger) Terminate() {
	d.doneOnce.Do(func() { close(d.done) })
}

// SetBreakpoints replaces the breakpoints for one file and returns what became
// of each, in the order asked for.
//
// Replacing rather than adding is DAP's model and the right one: an editor
// knows which markers a file has, and sending the whole set is the only message
// that cannot drift out of step with what the user can see. Other files'
// breakpoints are untouched.
func (d *Debugger) SetBreakpoints(file string, specs []BreakpointSpec) ([]Breakpoint, error) {
	if d.exited.Load() {
		return nil, errors.New("the program has already finished")
	}

	resolved := make([]Breakpoint, 0, len(specs))
	for _, spec := range specs {
		resolved = append(resolved, d.resolve(file, spec))
	}

	// The snapshot is rebuilt from every file's list rather than patched, so
	// the armed set can never disagree with the reported one.
	previous := d.breaks.Load()
	byFile := make(map[string][]Breakpoint, 4)
	if previous != nil {
		for name, list := range previous.byFile {
			if name != file {
				byFile[name] = list
			}
		}
	}
	byFile[file] = resolved

	sites := make(map[breakSite]Breakpoint, len(resolved))
	for _, list := range byFile {
		for _, bp := range list {
			if !bp.Verified {
				continue
			}
			for _, site := range d.sites[bp.Bound] {
				sites[site] = bp
			}
		}
	}

	d.breaks.Store(&breakSet{byFile: byFile, sites: sites})
	return resolved, nil
}

// resolve turns one requested file and line into a bound breakpoint.
func (d *Debugger) resolve(file string, spec BreakpointSpec) Breakpoint {
	d.nextBreakpointID++
	bp := Breakpoint{
		ID:       d.nextBreakpointID,
		File:     file,
		Line:     spec.Line,
		SkipHits: spec.SkipHits,
		hits:     &atomic.Int64{},
	}

	absLine, ok := d.vm.bytecode.ModuleLine(file, spec.Line)
	if !ok {
		bp.Message = fmt.Sprintf("%s is not one of the files this program was built from", file)
		return bp
	}

	bound, ok := d.nextLineWithCode(absLine)
	if !ok {
		bp.Message = "no code after this line: the program has nothing left to stop at"
		return bp
	}

	bp.Bound = bound
	bp.Verified = true

	// Bound is a blob line; the caller asked in file lines and has to be
	// answered in them, or an editor moves the marker to a line of another
	// module.
	if _, local, resolvedOK := d.vm.bytecode.ModuleAt(bound); resolvedOK {
		bp.Line = local
	} else {
		bp.Line = bound
	}
	return bp
}

// nextLineWithCode binds a line forward to the next one that emitted an
// instruction, which is decision 5 of the plan: a breakpoint on a blank line or
// a comment lands on the next line that can hold it.
func (d *Debugger) nextLineWithCode(line int) (int, bool) {
	at := sort.SearchInts(d.codeLines, line)
	if at >= len(d.codeLines) {
		return 0, false
	}
	return d.codeLines[at], true
}

// BreakpointLines reports the lines of file that can hold a breakpoint, which
// is what an editor asks for to show where a marker will actually land.
func (d *Debugger) BreakpointLines(file string) []int {
	lines := make([]int, 0, len(d.codeLines))
	for _, blob := range d.codeLines {
		path, local, ok := d.vm.bytecode.ModuleAt(blob)
		if !ok {
			// One module: the blob is the file.
			lines = append(lines, blob)
			continue
		}
		if file == "" || sameModuleFile(path, file) {
			lines = append(lines, local)
		}
	}
	sort.Ints(lines)
	return lines
}

// sameModuleFile compares two spellings of a path under the rule
// ByteCode.ModuleLine documents: exact first, base name second.
func sameModuleFile(spanPath, asked string) bool {
	if spanPath == asked {
		return true
	}
	return pathBase(spanPath) == pathBase(asked)
}

func pathBase(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// Frames is the call stack as it stands, innermost first. It is the traceback
// renderer's own walk, reused rather than reimplemented: a debugger and a crash
// report disagreeing about the stack would be a bug in one of them, and there
// is no way to tell which.
func (d *Debugger) Frames() ([]TracebackFrame, error) {
	if err := d.readable(); err != nil {
		return nil, err
	}
	return d.vm.Traceback(), nil
}

// Scopes returns the values visible in one frame, indexed as Frames returns
// them: 0 is the innermost.
//
// Arguments and Locals are separated even though arguments occupy the first
// local slots, because they answer different questions -- what was I called
// with, and what have I worked out since -- and listing a value twice in one
// pane is noise. Globals are the program's top level, which for frame 0 of a
// single-file program is the whole of its state.
func (d *Debugger) Scopes(frame int) ([]Scope, error) {
	if err := d.readable(); err != nil {
		return nil, err
	}

	target, err := d.frameAt(frame)
	if err != nil {
		return nil, err
	}

	fn := target.cl.Fn
	scopes := make([]Scope, 0, 3)

	if args := d.slotVariables(target, fn, 0, fn.NumParams); len(args) > 0 {
		scopes = append(scopes, Scope{Name: "Arguments", Variables: args})
	}
	if locals := d.slotVariables(target, fn, fn.NumParams, fn.NumLocals); len(locals) > 0 {
		scopes = append(scopes, Scope{Name: "Locals", Variables: locals})
	}
	if globals := d.globalVariables(); len(globals) > 0 {
		scopes = append(scopes, Scope{Name: "Globals", Variables: globals})
	}
	return scopes, nil
}

// slotVariables renders the frame slots in [from, to).
func (d *Debugger) slotVariables(frame *Frame, fn *object.CompiledFunction, from, to int) []Variable {
	if from < 0 || to > fn.NumLocals || from >= to {
		return nil
	}

	out := make([]Variable, 0, to-from)
	for slot := from; slot < to; slot++ {
		name := ""
		if slot < len(fn.LocalNames) {
			name = fn.LocalNames[slot]
		}
		if name == "" {
			// A slot whose name was taken over by a later declaration. It holds
			// a live value the program can no longer reach by name, so showing
			// it under a number is the only honest rendering.
			name = fmt.Sprintf("slot %d", slot)
		}

		index := frame.bp + slot
		if index < 0 || index >= len(d.vm.stack) {
			break
		}
		out = append(out, d.variable(name, d.vm.stack[index]))
	}
	return out
}

// globalVariables renders the program's top-level bindings.
//
// A slot that has not been assigned yet is left out rather than shown as unset:
// the globals array is allocated for the whole program, so every binding below
// the current line would otherwise appear as a variable that does not exist.
func (d *Debugger) globalVariables() []Variable {
	names := d.vm.bytecode.GlobalNames
	out := make([]Variable, 0, len(names))

	for slot, name := range names {
		if name == "" || slot >= len(d.vm.globals) {
			continue
		}
		if d.vm.globals[slot] == nil {
			if _, secure := d.vm.secureGlobals[slot]; !secure {
				continue
			}
		}
		// getGlobal, not a direct read: a global may be held in a secure
		// wrapper, and reading around that would show the encrypted form.
		out = append(out, d.variable(name, d.vm.getGlobal(slot)))
	}
	return out
}

// variable renders one value under a name.
func (d *Debugger) variable(name string, raw object.Object) Variable {
	value := d.unwrap(raw)
	if value == nil {
		return Variable{Name: name, Type: "unset", Value: "<unset>"}
	}

	v := Variable{
		Name:  name,
		Type:  string(value.Type()),
		Value: renderDebugValue(value),
	}
	if hasChildren(value) {
		v.Ref = d.handleFor(value)
	}
	return v
}

// unwrap turns a stored object into the value it stands for: decrypted, and
// with the cell a captured local lives in taken off. A cell is a storage
// location rather than a value, and showing one would show an address where the
// program sees a number.
func (d *Debugger) unwrap(raw object.Object) object.Object {
	if raw == nil {
		return nil
	}
	if cell, ok := raw.(*object.Cell); ok {
		if cell.Value == nil {
			return nil
		}
		raw = cell.Value
	}
	return d.vm.decryptForUse(raw)
}

// Children expands the value behind a handle. Handles come from Variable.Ref
// and are invalidated at every resume, because a handle into a value that has
// since been reassigned points at the wrong thing.
func (d *Debugger) Children(ref int) ([]Variable, error) {
	if err := d.readable(); err != nil {
		return nil, err
	}

	d.handleMu.Lock()
	value, ok := d.handles[ref]
	d.handleMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no value is held under reference %d; it belongs to an earlier stop", ref)
	}

	switch container := value.(type) {
	case *object.Array:
		out := make([]Variable, 0, len(container.Elements))
		for i, element := range container.Elements {
			if i >= maxDebugChildren {
				out = append(out, overflowVariable(len(container.Elements)-maxDebugChildren))
				break
			}
			out = append(out, d.variable(fmt.Sprintf("[%d]", i), element))
		}
		return out, nil

	case *object.Hash:
		type entry struct {
			key   string
			value object.Object
		}
		entries := make([]entry, 0, len(container.Pairs))
		for _, pair := range container.Pairs {
			key := "<key>"
			if pair.Key != nil {
				key = pair.Key.Inspect()
			}
			entries = append(entries, entry{key: key, value: pair.Value})
		}
		// Pairs is a Go map, so its order differs run to run. Hash.Inspect
		// sorts for exactly that reason and a variables pane that reshuffled
		// itself on every step would be unreadable.
		sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })

		out := make([]Variable, 0, len(entries))
		for i, e := range entries {
			if i >= maxDebugChildren {
				out = append(out, overflowVariable(len(entries)-maxDebugChildren))
				break
			}
			out = append(out, d.variable(e.key, e.value))
		}
		return out, nil

	case *object.Struct:
		names := make([]string, 0, len(container.Fields))
		for field := range container.Fields {
			names = append(names, field)
		}
		sort.Strings(names)

		out := make([]Variable, 0, len(names))
		for _, field := range names {
			out = append(out, d.variable(field, container.Fields[field]))
		}
		return out, nil
	}

	return nil, nil
}

func overflowVariable(remaining int) Variable {
	return Variable{
		Name:  "...",
		Type:  "note",
		Value: fmt.Sprintf("%d more not shown", remaining),
	}
}

// Evaluate answers a bare identifier against one frame: its locals first, then
// the program's globals, which is the order the compiler resolves names in.
//
// Anything else is refused with the reason. Evaluating `xs[i].total` means
// compiling it in the frame's scope, and the scope is the compiler's symbol
// table, which does not travel in the artifact. A debugger that answered such
// an expression would be guessing, and guessing is what a watch window is for
// checking.
func (d *Debugger) Evaluate(frame int, expression string) (Variable, error) {
	if err := d.readable(); err != nil {
		return Variable{}, err
	}

	name := strings.TrimSpace(expression)
	if !isBareIdentifier(name) {
		return Variable{}, fmt.Errorf(
			"only a plain variable name can be evaluated here, not %q: an expression has to be compiled "+
				"in this frame's scope, and a compiled program does not carry its scopes", expression)
	}

	target, err := d.frameAt(frame)
	if err != nil {
		return Variable{}, err
	}

	fn := target.cl.Fn
	for slot := fn.NumLocals - 1; slot >= 0; slot-- {
		// Backwards: a name taken over by a later declaration resolves to the
		// later slot, which is what the compiler's store does and therefore
		// what the running program sees.
		if slot < len(fn.LocalNames) && fn.LocalNames[slot] == name {
			index := target.bp + slot
			if index < 0 || index >= len(d.vm.stack) {
				break
			}
			return d.variable(name, d.vm.stack[index]), nil
		}
	}

	for slot, global := range d.vm.bytecode.GlobalNames {
		if global != name || slot >= len(d.vm.globals) {
			continue
		}
		return d.variable(name, d.vm.getGlobal(slot)), nil
	}

	return Variable{}, fmt.Errorf("no variable called %q is in scope here", name)
}

// isBareIdentifier reports whether s is a single name, which is the whole of
// what Evaluate accepts.
func isBareIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_':
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// frameAt maps a display index -- 0 for the innermost -- to the VM frame,
// applying the same skip rule Traceback does so the two stay aligned.
func (d *Debugger) frameAt(index int) (*Frame, error) {
	if index < 0 {
		return nil, fmt.Errorf("frame %d does not exist", index)
	}

	seen := 0
	for i := d.vm.frameIndex - 1; i >= 0; i-- {
		frame := d.vm.frames[i]
		if frame == nil || frame.cl == nil || frame.cl.Fn == nil {
			continue
		}
		if seen == index {
			return frame, nil
		}
		seen++
	}
	return nil, fmt.Errorf("frame %d does not exist: the stack is %d deep", index, seen)
}

// readable reports whether VM state can be read right now.
func (d *Debugger) readable() error {
	if d.exited.Load() {
		return errors.New("the program has finished; its state is gone")
	}
	if !d.stopped.Load() {
		return ErrNotStopped
	}
	return nil
}

func (d *Debugger) handleFor(value object.Object) int {
	d.handleMu.Lock()
	defer d.handleMu.Unlock()

	d.nextHandle++
	d.handles[d.nextHandle] = value
	return d.nextHandle
}

func (d *Debugger) resetHandles() {
	d.handleMu.Lock()
	defer d.handleMu.Unlock()

	if len(d.handles) > 0 {
		d.handles = make(map[int]object.Object, 8)
	}
}

// hasChildren reports whether a value is worth expanding. Only the three
// containers the language builds by hand are expanded; everything else renders
// completely in one line, and an expander that opened a leaf would show an
// empty list where a reader expects detail.
func hasChildren(value object.Object) bool {
	switch container := value.(type) {
	case *object.Array:
		return len(container.Elements) > 0
	case *object.Hash:
		return len(container.Pairs) > 0
	case *object.Struct:
		return len(container.Fields) > 0
	}
	return false
}

// renderDebugValue renders one value for a variables pane: on one line, capped,
// and truncated rather than summarised so that what is shown is a prefix of
// what is there.
func renderDebugValue(value object.Object) string {
	if value == nil {
		return "<unset>"
	}

	// Bytes renders as full hex through Inspect, because Inspect doubles as the
	// identity function for equality. A pane only ever wanted a preview, so it
	// asks for one rather than building a megabyte of hex to then cut it back.
	if buf, ok := value.(*object.Bytes); ok {
		return buf.Preview(maxDebugValue / 4)
	}

	text := strings.Join(strings.Fields(value.Inspect()), " ")
	if len(text) > maxDebugValue {
		text = text[:maxDebugValue-3] + "..."
	}
	if text == "" {
		return string(value.Type())
	}
	return text
}

// clearUnsetLocals blanks the slots between a new frame's arguments and the end
// of its locals.
//
// The calling convention leaves them holding whatever the previous frame left
// on the stack, which the program never reads -- every local is assigned before
// it is used -- but a debugger reads them all, and would show a dead value from
// an unrelated call under the name of a variable whose declaration has not run
// yet. Cheaper to be honest than to explain it.
//
// It runs only with a debugger attached, so the calling convention is unchanged
// for every ordinary run.
func (vm *VM) clearUnsetLocals(frame *Frame, fn *object.CompiledFunction) {
	for slot := fn.NumParams; slot < fn.NumLocals; slot++ {
		index := frame.bp + slot
		if index < 0 || index >= len(vm.stack) {
			return
		}
		vm.stack[index] = nil
	}
}
