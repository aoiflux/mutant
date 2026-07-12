package repl

import "testing"

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
