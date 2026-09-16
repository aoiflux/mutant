package dap

import "encoding/json"

// The message envelopes. Every DAP message carries a sequence number and a
// type; the rest depends on which of the three it is.

type request struct {
	Seq     int    `json:"seq"`
	Type    string `json:"type"`
	Command string `json:"command"`

	// Arguments stay raw until the handler for this command decodes them into
	// the shape it expects. Decoding centrally would mean one struct carrying
	// every command's fields, where a field belonging to another command is
	// indistinguishable from one this command omitted.
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type response struct {
	Seq        int    `json:"seq"`
	Type       string `json:"type"`
	RequestSeq int    `json:"request_seq"`
	Success    bool   `json:"success"`
	Command    string `json:"command"`

	// Message is shown to the user when Success is false. It is the whole of
	// what a person sees when something does not work, so every refusal in this
	// package fills it with a sentence rather than a code.
	Message string `json:"message,omitempty"`
	Body    any    `json:"body,omitempty"`
}

type event struct {
	Seq   int    `json:"seq"`
	Type  string `json:"type"`
	Event string `json:"event"`
	Body  any    `json:"body,omitempty"`
}

// capabilities is what the adapter answers `initialize` with. Everything not
// listed is absent, and absent means false -- which is the honest answer for
// each of the ones left out, and the reason they are commented rather than
// silently missing.
type capabilities struct {
	SupportsConfigurationDoneRequest   bool `json:"supportsConfigurationDoneRequest"`
	SupportsTerminateRequest           bool `json:"supportsTerminateRequest"`
	SupportsBreakpointLocationsRequest bool `json:"supportsBreakpointLocationsRequest"`

	// Hit counts are supported because a count is not an expression. General
	// conditions and data breakpoints are not, and evaluateForHovers is not
	// either: this adapter answers a bare name and refuses anything else, and
	// an editor that asked it to evaluate every identifier under the cursor
	// would collect a refusal for each one. See decision 7 in
	// plans/T1_DEBUGGER.md.
	SupportsHitConditionalBreakpoints bool `json:"supportsHitConditionalBreakpoints"`

	// Every value shown is read, never written: setVariable and setExpression
	// would mean assigning into a running frame, which is a different feature
	// with a different risk, and this is a debugger for evidence-handling code.
	SupportsSetVariable bool `json:"supportsSetVariable"`
}

// source names a file to the editor.
type source struct {
	Name string `json:"name,omitempty"`
	Path string `json:"path,omitempty"`
}

type sourceBreakpoint struct {
	Line         int    `json:"line"`
	Condition    string `json:"condition,omitempty"`
	HitCondition string `json:"hitCondition,omitempty"`
	LogMessage   string `json:"logMessage,omitempty"`
}

type setBreakpointsArguments struct {
	Source      source             `json:"source"`
	Breakpoints []sourceBreakpoint `json:"breakpoints,omitempty"`

	// Lines is the deprecated form, still sent by some clients. It is read only
	// when Breakpoints is absent.
	Lines []int `json:"lines,omitempty"`
}

type breakpoint struct {
	ID       int     `json:"id,omitempty"`
	Verified bool    `json:"verified"`
	Message  string  `json:"message,omitempty"`
	Source   *source `json:"source,omitempty"`
	Line     int     `json:"line,omitempty"`
}

type launchArguments struct {
	// Program is the .mut to debug. It may be omitted when the adapter was
	// started with one on the command line, which is how a client that has no
	// place to put it (a bare nvim-dap config) reaches the same result.
	Program string `json:"program,omitempty"`

	StopOnEntry bool `json:"stopOnEntry,omitempty"`

	// ModulePaths are extra directories to resolve imports from, the launch
	// request's spelling of --module-path. Configuration arrives here or in
	// argv and nowhere else: no environment variables, ever. See
	// docs/CONFIGURATION_POLICY.md.
	ModulePaths []string `json:"modulePaths,omitempty"`

	// NoDebug means "just run it". The session still reports output and the
	// exit, it simply never stops.
	NoDebug bool `json:"noDebug,omitempty"`
}

type stackTraceArguments struct {
	ThreadID   int `json:"threadId"`
	StartFrame int `json:"startFrame,omitempty"`
	Levels     int `json:"levels,omitempty"`
}

type stackFrame struct {
	ID        int     `json:"id"`
	Name      string  `json:"name"`
	Source    *source `json:"source,omitempty"`
	Line      int     `json:"line"`
	Column    int     `json:"column"`
	EndLine   int     `json:"endLine,omitempty"`
	EndColumn int     `json:"endColumn,omitempty"`
}

type scopesArguments struct {
	FrameID int `json:"frameId"`
}

type scope struct {
	Name               string `json:"name"`
	PresentationHint   string `json:"presentationHint,omitempty"`
	VariablesReference int    `json:"variablesReference"`

	// Expensive tells the editor whether to expand the scope without being
	// asked. Nothing here is expensive: every value is already in memory.
	Expensive bool `json:"expensive"`
}

type variablesArguments struct {
	VariablesReference int `json:"variablesReference"`
}

type variable struct {
	Name               string `json:"name"`
	Value              string `json:"value"`
	Type               string `json:"type,omitempty"`
	VariablesReference int    `json:"variablesReference"`
}

type evaluateArguments struct {
	Expression string `json:"expression"`
	FrameID    int    `json:"frameId,omitempty"`
	Context    string `json:"context,omitempty"`
}

type breakpointLocationsArguments struct {
	Source  source `json:"source"`
	Line    int    `json:"line"`
	EndLine int    `json:"endLine,omitempty"`
}

type breakpointLocation struct {
	Line int `json:"line"`
}

type thread struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// Event bodies.

type stoppedBody struct {
	Reason            string `json:"reason"`
	Description       string `json:"description,omitempty"`
	ThreadID          int    `json:"threadId"`
	AllThreadsStopped bool   `json:"allThreadsStopped"`
	HitBreakpointIDs  []int  `json:"hitBreakpointIds,omitempty"`
}

type continuedBody struct {
	ThreadID            int  `json:"threadId"`
	AllThreadsContinued bool `json:"allThreadsContinued"`
}

type outputBody struct {
	Category string `json:"category,omitempty"`
	Output   string `json:"output"`
}

type exitedBody struct {
	ExitCode int `json:"exitCode"`
}

// The single thread this adapter reports.
//
// A mutant program has one executor. spawn and pmap build sibling VMs, which
// have no debugger attached and are not stepped, so reporting them as threads
// would offer the user a stack they cannot stop in. One honest thread beats
// several decorative ones.
const (
	mainThreadID   = 1
	mainThreadName = "main"
)
