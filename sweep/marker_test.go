package sweep

import (
	"strings"
	"testing"
)

func TestAFileWithNoMarkerIsAnOrdinaryExample(t *testing.T) {
	marker, err := ParseMarker(`putln("hello");`)
	if err != nil {
		t.Fatalf("unmarked file: %s", err)
	}
	if marker.Mode != ModeRun {
		t.Fatalf("unmarked file reported mode %q, want %q", marker.Mode, ModeRun)
	}
	if marker.Explicit {
		t.Fatal("unmarked file reported an explicit marker")
	}
}

func TestAMarkerReportsItsModeReasonAndLine(t *testing.T) {
	source := "// demo.mut\n// mutant:sweep server -- binds 127.0.0.1:8140\n\nputln(1);"

	marker, err := ParseMarker(source)
	if err != nil {
		t.Fatalf("parse: %s", err)
	}
	if marker.Mode != ModeServer {
		t.Fatalf("mode %q, want %q", marker.Mode, ModeServer)
	}
	if marker.Reason != "binds 127.0.0.1:8140" {
		t.Fatalf("reason %q, want the text after the separator", marker.Reason)
	}
	if marker.Line != 2 {
		t.Fatalf("line %d, want 2", marker.Line)
	}
	if !marker.Explicit {
		t.Fatal("an explicit marker reported itself as absent")
	}
}

// A marker exists so a future reader can tell a deliberate exclusion from a
// broken program. A mode with no reason does not do that job, so it is rejected
// rather than accepted silently.
func TestAMarkerNeedsAReason(t *testing.T) {
	_, err := ParseMarker("// mutant:sweep server\n")
	if err == nil {
		t.Fatal("a mode with no reason was accepted")
	}
	if !strings.Contains(err.Error(), "reason") {
		t.Fatalf("the error does not mention the missing reason: %s", err)
	}
}

func TestAnUnknownModeIsRejectedAndTheKnownOnesAreListed(t *testing.T) {
	_, err := ParseMarker("// mutant:sweep deamon -- typo\n")
	if err == nil {
		t.Fatal("an unknown mode was accepted")
	}
	for _, mode := range Modes() {
		if !strings.Contains(err.Error(), string(mode)) {
			t.Fatalf("the error does not offer %q as an alternative: %s", mode, err)
		}
	}
}

func TestAModeWithNothingAfterItIsRejected(t *testing.T) {
	if _, err := ParseMarker("// mutant:sweep\n"); err == nil {
		t.Fatal("a directive naming no mode was accepted")
	}
}

func TestTwoMarkersAreRejected(t *testing.T) {
	source := "// mutant:sweep server -- one\n// mutant:sweep run -- two\n"

	_, err := ParseMarker(source)
	if err == nil {
		t.Fatal("a file with two markers was accepted; which one wins is undefined")
	}
	if !strings.Contains(err.Error(), "lines 1 and 2") {
		t.Fatalf("the error does not name both lines: %s", err)
	}
}

// The directive word has to end at a word boundary, or a comment that merely
// starts with the same letters becomes a directive.
func TestASimilarWordIsNotADirective(t *testing.T) {
	marker, err := ParseMarker("// mutant:sweeper is not this tool\n")
	if err != nil {
		t.Fatalf("parse: %s", err)
	}
	if marker.Explicit {
		t.Fatal("`mutant:sweeper` was read as a `mutant:sweep` directive")
	}
}

// The reason a marker is read from comment trivia rather than by scanning lines:
// every one of these examples documents its own use of net_serve in prose, and
// a program is free to print the directive text.
func TestADirectiveInsideAStringIsNotADirective(t *testing.T) {
	marker, err := ParseMarker(`putln("// mutant:sweep server -- not a marker");`)
	if err != nil {
		t.Fatalf("parse: %s", err)
	}
	if marker.Explicit {
		t.Fatal("text inside a string literal was read as a marker")
	}
}

func TestClassifyReadsCallsNotProse(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   Mode
	}{
		{
			name:   "a listener makes it a server",
			source: `let ln, err = net_listen("127.0.0.1:8140");`,
			want:   ModeServer,
		},
		{
			name:   "a TLS listener counts too",
			source: `let ln, err = net_tls_listen(addr, cert, key, opts);`,
			want:   ModeServer,
		},
		{
			name:   "serve_conn makes it a handler",
			source: `let conn, err = serve_conn();`,
			want:   ModeServeHandler,
		},
		{
			name:   "a handler that also listens reads as a handler",
			source: `let conn, e = serve_conn(); let ln, f = net_listen(addr);`,
			want:   ModeServeHandler,
		},
		{
			name:   "prose about net_serve is not a call",
			source: "// This program is dispatched by net_serve and reads serve_conn().\nputln(1);",
			want:   ModeRun,
		},
		{
			name:   "a builtin name in a string is not a call",
			source: `putln("net_listen(addr) opens a listener");`,
			want:   ModeRun,
		},
		{
			name:   "naming a builtin without calling it is not a call",
			source: `let f = net_listen;`,
			want:   ModeRun,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Classify(test.source); got != test.want {
				t.Fatalf("classified as %q, want %q", got, test.want)
			}
		})
	}
}

func TestAFileThatMayNotReturnHasToSayWhichItIs(t *testing.T) {
	err := Check(`let ln, err = net_listen("127.0.0.1:8140");`)
	if err == nil {
		t.Fatal("an unmarked listening program was accepted")
	}
	if !strings.Contains(err.Error(), string(ModeServer)) {
		t.Fatalf("the error does not suggest the likely mode: %s", err)
	}
}

// The rule that keeps markers from rotting. A marker left behind after a rewrite
// makes a sweep skip an example forever, and nothing else would notice.
func TestAStaleMarkerIsRejected(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "server on a program that never listens",
			source: "// mutant:sweep server -- it used to listen\nputln(1);",
			want:   "never opens a listener",
		},
		{
			name:   "serve-handler on a program that never reads a connection",
			source: "// mutant:sweep serve-handler -- it used to be dispatched\nputln(1);",
			want:   "never calls serve_conn()",
		},
		{
			name:   "serve-handler on a server",
			source: "// mutant:sweep serve-handler -- wrong mode\nlet ln, e = net_listen(addr);",
			want:   "never calls serve_conn()",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := Check(test.source)
			if err == nil {
				t.Fatal("a stale marker was accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("the error does not say why: %s", err)
			}
		})
	}
}

// A marker says what a sweep should do with a file, not what category the file
// belongs to. portscan_service's handler calls serve_conn() and still runs
// standalone, so `run` has to stay available with a reason.
func TestRunStaysAvailableToAnyFile(t *testing.T) {
	sources := []string{
		"// mutant:sweep run -- checks for null and prints a notice\nlet conn, e = serve_conn();",
		"// mutant:sweep run -- opens a listener, reports the handle and exits\nlet ln, e = net_listen(addr);",
	}

	for _, source := range sources {
		if err := Check(source); err != nil {
			t.Fatalf("an explicit run marker was rejected: %s", err)
		}
	}
}

func TestAnOrdinaryExampleNeedsNoMarker(t *testing.T) {
	if err := Check(`putln("hello");`); err != nil {
		t.Fatalf("an ordinary example was asked for a marker: %s", err)
	}
}
