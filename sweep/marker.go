// Package sweep describes how each Mutant example expects to be run.
//
// Sweeping the examples -- compile every .mut, run it, expect it to succeed --
// is the cheapest end-to-end check this repo has, and it has caught real engine
// defects. But a handful of examples cannot pass that check by construction:
// some are net_serve handlers that only mean anything when a listener dispatches
// to them, and the rest bind a port and run until they are interrupted. A sweep
// with no way to know that reports them as failures and timeouts, and the next
// person to read the output cannot tell those apart from a program that actually
// broke.
//
// A `// mutant:sweep <mode> -- <reason>` comment says which it is. The mode is
// checked against what the file actually calls, so a marker cannot quietly go
// stale -- which a hand-maintained list of file names would, and which is how
// the stale opcode-remap list survived long enough to become a defect.
package sweep

import (
	"fmt"
	"strings"

	"mutant/lexer"
	"mutant/token"
)

// Mode is how a sweep must treat one example.
type Mode string

const (
	// ModeRun is an ordinary example: compile it, run it, expect it to finish
	// successfully. This is the default, and most examples never say it.
	ModeRun Mode = "run"

	// ModeServer binds a port and serves until interrupted. A sweep starts it,
	// confirms it is still alive after a moment, and stops it. Exiting early is
	// the failure; running forever is the point.
	ModeServer Mode = "server"

	// ModeServeHandler is dispatched by net_serve and reads its connection from
	// serve_conn(). Standalone it has no connection and cannot do its job, so a
	// sweep compiles it and stops there.
	ModeServeHandler Mode = "serve-handler"
)

// Directive introduces a marker inside a line comment.
const Directive = "mutant:sweep"

// reasonSeparator divides the mode from the explanation that follows it.
const reasonSeparator = "--"

// Modes lists every mode a marker may name, in the order help text should show
// them.
func Modes() []Mode { return []Mode{ModeRun, ModeServer, ModeServeHandler} }

// Marker is what one example says about itself.
type Marker struct {
	Mode Mode
	// Reason is the text after `--`. Empty only for an unmarked file.
	Reason string
	// Line is the 1-based line the directive sits on, or 0 when there is none.
	Line int
	// Explicit distinguishes "this file says it is an ordinary example" from
	// "this file says nothing", which Check treats differently.
	Explicit bool
}

// String renders the marker as the comment line that would produce it.
func (m Marker) String() string {
	if !m.Explicit {
		return ""
	}
	return fmt.Sprintf("// %s %s %s %s", Directive, m.Mode, reasonSeparator, m.Reason)
}

// ParseMarker reads the sweep marker out of a Mutant source file.
//
// It reads the lexer's comment trivia rather than scanning lines, so a directive
// written inside a string literal is not a directive.
func ParseMarker(src string) (Marker, error) {
	found := []Marker{}

	for _, comment := range commentsOf(src) {
		body, ok := directiveBody(comment.Text)
		if !ok {
			continue
		}

		marker, err := parseDirectiveBody(body)
		if err != nil {
			return Marker{}, fmt.Errorf("line %d: %w", comment.Start.Line, err)
		}
		marker.Line = comment.Start.Line
		found = append(found, marker)
	}

	switch len(found) {
	case 0:
		return Marker{Mode: ModeRun}, nil
	case 1:
		return found[0], nil
	default:
		return Marker{}, fmt.Errorf("two %s markers, on lines %d and %d; a file gets one",
			Directive, found[0].Line, found[1].Line)
	}
}

// directiveBody reports whether a comment is a sweep directive, and returns what
// follows the directive word. It requires whitespace (or nothing) after the
// directive so that a comment about, say, `mutant:sweeper` is not a directive.
func directiveBody(text string) (string, bool) {
	rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(text), "//"))
	if !strings.HasPrefix(rest, Directive) {
		return "", false
	}

	rest = rest[len(Directive):]
	if rest != "" && !strings.HasPrefix(rest, " ") && !strings.HasPrefix(rest, "\t") {
		return "", false
	}
	return strings.TrimSpace(rest), true
}

func parseDirectiveBody(body string) (Marker, error) {
	if body == "" {
		return Marker{}, fmt.Errorf("%s names no mode; expected one of %s", Directive, modeList())
	}

	modeText, reason := body, ""
	if head, tail, found := strings.Cut(body, reasonSeparator); found {
		modeText, reason = strings.TrimSpace(head), strings.TrimSpace(tail)
	}

	fields := strings.Fields(modeText)
	if len(fields) != 1 {
		return Marker{}, fmt.Errorf("%s takes one mode then `%s <reason>`, got %q",
			Directive, reasonSeparator, body)
	}

	mode := Mode(fields[0])
	if !known(mode) {
		return Marker{}, fmt.Errorf("unknown mode %q; expected one of %s", fields[0], modeList())
	}
	if reason == "" {
		return Marker{}, fmt.Errorf("mode %q needs a reason: `// %s %s %s <why>`",
			mode, Directive, mode, reasonSeparator)
	}

	return Marker{Mode: mode, Reason: reason, Explicit: true}, nil
}

func known(mode Mode) bool {
	for _, candidate := range Modes() {
		if candidate == mode {
			return true
		}
	}
	return false
}

func modeList() string {
	names := make([]string, 0, len(Modes()))
	for _, mode := range Modes() {
		names = append(names, string(mode))
	}
	return strings.Join(names, ", ")
}

// Classify reports the mode a file's own code implies.
//
// It looks for calls, by token, so a builtin named in a comment or inside a
// string is not a call -- which matters here, because every one of these
// examples documents its own use of net_serve and serve_conn in its header.
func Classify(src string) Mode {
	handler, listener := serveShape(src)

	// serve_conn is the stronger signal: a handler has no connection at all
	// unless a listener dispatched to it, so that is the likelier mode when a
	// file does both. Neither answer binds the author -- see Check.
	switch {
	case handler:
		return ModeServeHandler
	case listener:
		return ModeServer
	default:
		return ModeRun
	}
}

// calledNames collects every identifier that appears immediately before a `(`.
func calledNames(src string) map[string]bool {
	names := map[string]bool{}
	previous := token.Token{}

	lex := lexer.New(src)
	for tok := lex.NextToken(); tok.Type != token.EOF; tok = lex.NextToken() {
		if tok.Type == token.LPAREN && previous.Type == token.IDENT {
			names[previous.Literal] = true
		}
		previous = tok
	}
	return names
}

func commentsOf(src string) []token.Comment {
	lex := lexer.New(src)
	for tok := lex.NextToken(); tok.Type != token.EOF; tok = lex.NextToken() {
		// Draining the lexer is what collects the comment trivia.
		_ = tok
	}
	return lex.Comments()
}
