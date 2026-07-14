package repl

import (
	"bytes"
	"strings"
	"testing"

	"mutant/object"
)

func TestIsExitCommand(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "exit", input: "exit", want: true},
		{name: "quit", input: "quit", want: true},
		{name: "exit with semicolon", input: "exit;", want: true},
		{name: "quit with semicolon", input: "quit;", want: true},
		{name: "exit with spaces and semicolons", input: "  exit ;;  ", want: true},
		{name: "quit uppercase", input: "QUIT", want: true},
		{name: "exit uppercase mixed", input: "ExIt", want: true},
		{name: "empty", input: "", want: false},
		{name: "non-exit phrase", input: "exit now", want: false},
		{name: "function style", input: "quit()", want: false},
		{name: "identifier", input: "quitter", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isExitCommand(tt.input)
			if got != tt.want {
				t.Fatalf("isExitCommand(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseHelpCall(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantTopic string
		wantMode  string
		wantOK    bool
	}{
		{name: "empty call", input: "help()", wantTopic: "", wantMode: "", wantOK: true},
		{name: "topic only", input: "help(\"keywords\")", wantTopic: "keywords", wantMode: "", wantOK: true},
		{name: "topic and mode", input: "help(\"builtins\", \"all\")", wantTopic: "builtins", wantMode: "all", wantOK: true},
		{name: "missing quote", input: "help(builtins)", wantOK: false},
		{name: "too many args", input: "help(\"a\", \"b\", \"c\")", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			topic, mode, ok := parseHelpCall(tt.input)
			if ok != tt.wantOK {
				t.Fatalf("parseHelpCall(%q) ok=%v, want %v", tt.input, ok, tt.wantOK)
			}
			if topic != tt.wantTopic {
				t.Fatalf("parseHelpCall(%q) topic=%q, want %q", tt.input, topic, tt.wantTopic)
			}
			if mode != tt.wantMode {
				t.Fatalf("parseHelpCall(%q) mode=%q, want %q", tt.input, mode, tt.wantMode)
			}
		})
	}
}

func TestHandleCompleteCommandIncludesSessionSymbols(t *testing.T) {
	env := object.NewEnvironment()
	env.Set("session_symbol", &object.Integer{Value: 1})
	var out bytes.Buffer

	handled := handleCompleteCommand(":complete session_", &out, env)
	if !handled {
		t.Fatal("expected :complete command to be handled")
	}

	if !strings.Contains(out.String(), "session_symbol") {
		t.Fatalf("completion output missing session symbol: %q", out.String())
	}
}

func TestHandleMetaHelpCommand(t *testing.T) {
	var out bytes.Buffer
	handled := handleMetaHelpCommand(":help docs", &out, object.NewEnvironment())
	if !handled {
		t.Fatal("expected :help command to be handled")
	}

	if !strings.Contains(out.String(), "https://mudocs.aoiflux.xyz") {
		t.Fatalf("help output missing docs URL: %q", out.String())
	}
}

func TestHandleMetaHelpCommandPlainHelpAlias(t *testing.T) {
	var out bytes.Buffer
	handled := handleMetaHelpCommand("help", &out, object.NewEnvironment())
	if !handled {
		t.Fatal("expected plain help command to be handled")
	}

	if !strings.Contains(out.String(), "Mutant REPL help") {
		t.Fatalf("plain help output missing overview: %q", out.String())
	}
}

func TestCompletionPrefix(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{name: "empty", line: "", want: ""},
		{name: "single token", line: "tex", want: "tex"},
		{name: "after space", line: "let x = tex", want: "let x = tex"},
		{name: "help call", line: "help(\"tex", want: "help(\"tex"},
		{name: "meta command", line: ":help bui", want: ":help bui"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := completionPrefix(tt.line)
			if got != tt.want {
				t.Fatalf("completionPrefix(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestInteractiveLineReaderAddHistory(t *testing.T) {
	reader := &interactiveLineReader{history: make([]historyEntry, 0, 8)}
	reader.AddHistory("", false)
	reader.AddHistory("   ", true)
	if len(reader.history) != 0 {
		t.Fatalf("expected empty history for blank lines, got %d", len(reader.history))
	}

	reader.AddHistory("let x = 1", false)
	reader.AddHistory("help", true)
	if len(reader.history) != 2 {
		t.Fatalf("expected 2 history entries, got %d", len(reader.history))
	}
	if reader.history[0].line != "let x = 1" || reader.history[0].failed {
		t.Fatalf("unexpected first history entry: %+v", reader.history[0])
	}
	if reader.history[1].line != "help" || !reader.history[1].failed {
		t.Fatalf("unexpected second history entry: %+v", reader.history[1])
	}
}
