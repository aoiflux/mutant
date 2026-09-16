package analyzer

import (
	"strings"
	"testing"
)

// injectionMessages returns the messages of every commandInjection diagnostic
// in src. Its one message says "The interpreter parses the finished string".
func injectionMessages(t *testing.T, src string) []string {
	t.Helper()

	snapshot := New().Analyze(src)
	out := make([]string, 0, 2)
	for _, d := range Diagnostics(snapshot, DefaultLintConfig()) {
		if d.Source != nil && *d.Source == "mutant-lint" && strings.Contains(d.Message, "The interpreter parses the finished string") {
			out = append(out, d.Message)
		}
	}
	return out
}

func TestCommandInjectionFires(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			"a value interpolated into a shell command",
			`let out, err = exec_string("ls ${directory}");`,
			"interpolated into the command `exec_string` gives to a shell",
		},
		{
			"a value concatenated into a shell command",
			`let out, err = exec_string("ls " + directory);`,
			"concatenated into the command `exec_string`",
		},
		{
			"a value in the middle of a concatenation chain",
			`let out, err = exec_string("cat " + path + " | wc -l");`,
			"concatenated into the command `exec_string`",
		},
		{
			// cmd_run only joins the lines it was given, so the report belongs
			// where the string is assembled.
			"a value concatenated into a builder line",
			`let b, err = cmd_builder("sh");
let b2, add_err = cmd_add(b, "grep " + pattern + " /var/log/syslog");`,
			"`cmd_add` gives to a shell, once `cmd_run` is called",
		},
		{
			// The shape that was found in examples/text/phishing_url_analyzer.mut
			// while this rule was being written: an attacker-authored URL going
			// inside a Lua single-quoted string.
			"a value concatenated into a Lua script",
			`let script = "local u='" + url + "'; return u";
let out, err = lua_run_string(script);`,
			"the Lua interpreter",
		},
		{
			"a command assembled under a name first",
			`let command = "ping -c 1 " + host;
let out, err = exec_string(command);`,
			"concatenated into the command `exec_string`",
		},
		{
			"a call result interpolated",
			`let out, err = exec_string("whois ${gets()}");`,
			"interpolated into",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			messages := injectionMessages(t, tc.src)
			if len(messages) != 1 {
				t.Fatalf("want exactly one report, got %d: %v", len(messages), messages)
			}
			if !strings.Contains(messages[0], tc.want) {
				t.Fatalf("message %q does not contain %q", messages[0], tc.want)
			}
		})
	}
}

func TestCommandInjectionStaysQuiet(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			"a fixed command",
			`let out, err = exec_string("systeminfo");`,
		},
		{
			// A constant that happens to be written in pieces has nothing in
			// it the author did not put there.
			"a constant written as a concatenation",
			`let out, err = exec_string("ls " + "-la");`,
		},
		{
			"a constant written with a literal hole",
			`let out, err = exec_string("ls ${"-la"}");`,
		},
		{
			// examples/security/command_sandbox.mut: the whole command arrives
			// as one value. A real question, but about where the value came
			// from rather than about what this line does with it.
			"a whole command in a variable",
			`for (cmd in commands) { let out, xerr = exec_string(cmd); };`,
		},
		{
			// The rule has to have a way to comply, or it is a rule people
			// switch off.
			"a value stripped of the delimiter first",
			`let out, err = exec_string("ls " + text_replace(directory, "'", ""));`,
		},
		{
			"a value percent-encoded first",
			`let out, err = exec_string("curl https://x/" + url_encode(path));`,
		},
		{
			"a sanitised value bound to a name",
			`let safe = text_replace(url, "'", "");
let script = "local u='" + safe + "'; return u";
let out, err = lua_run_string(script);`,
		},
		{
			"a builder line that is fixed text",
			`let b2, err = cmd_add(b, "Get-Process | ConvertTo-Json");`,
		},
		{
			"concatenation that never reaches a command",
			`let label = "user " + name;
putln(label);`,
		},
		{
			"a shadowed builtin",
			`let exec_string = fn(c) { return c; };
let out = exec_string("ls " + directory);`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if messages := injectionMessages(t, tc.src); len(messages) != 0 {
				t.Fatalf("want silence, got %v", messages)
			}
		})
	}
}

func TestCommandInjectionCanBeTurnedOff(t *testing.T) {
	src := `let out, err = exec_string("ls " + directory);`

	config := DefaultLintConfig()
	config.CommandInjection = LintSeverityOff

	snapshot := New().Analyze(src)
	for _, d := range Diagnostics(snapshot, config) {
		if strings.Contains(d.Message, "The interpreter parses the finished string") {
			t.Fatalf("rule is off but still reported: %s", d.Message)
		}
	}
}
