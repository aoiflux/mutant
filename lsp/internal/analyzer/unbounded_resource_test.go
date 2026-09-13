package analyzer

import (
	"strings"
	"testing"
)

// unboundedMessages returns the messages of every unboundedResource diagnostic
// in src. Both of its messages say "raises at run time".
func unboundedMessages(t *testing.T, src string) []string {
	t.Helper()

	snapshot := New().Analyze(src)
	out := make([]string, 0, 2)
	for _, d := range Diagnostics(snapshot, DefaultLintConfig()) {
		if d.Source != nil && *d.Source == "mutant-lint" && strings.Contains(d.Message, "raises at run time") {
			out = append(out, d.Message)
		}
	}
	return out
}

func TestUnboundedResourceFires(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			// The call this rule exists for: it reads as a reasonable way to
			// sweep a corporate network, and it fails.
			"a class-A sweep",
			`let hosts = cidr_hosts("10.0.0.0/8");`,
			"24 -- 16777216 addresses",
		},
		{
			"one bit over the line",
			`let hosts = cidr_hosts("10.0.0.0/11");`,
			"21 -- 2097152 addresses",
		},
		{
			"an IPv6 prefix",
			`let hosts = cidr_hosts("2001:db8::/32");`,
			"has 96 -- 79228162514264337593543950336 addresses",
		},
		{
			"a CIDR reached through a name",
			`let scope = "192.168.0.0/8";
let hosts = cidr_hosts(scope);`,
			"addresses",
		},
		{
			"a range past the cap",
			`let all = range(0, 20000000);`,
			"asks for 20000000",
		},
		{
			"a descending range past the cap",
			`let all = range(0, -20000000, -1);`,
			"asks for 20000000",
		},
		{
			// The step is what decides the length, so a rule that ignored it
			// would report a range that is in fact fine.
			"a stepped range that is still too long",
			`let all = range(0, 60000000, 2);`,
			"asks for 30000000",
		},
		{
			"bounds that overflow a signed subtraction",
			`let all = range(-9000000000000000000, 9000000000000000000);`,
			"asks for 18000000000000000000",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			messages := unboundedMessages(t, tc.src)
			if len(messages) != 1 {
				t.Fatalf("want exactly one report, got %d: %v", len(messages), messages)
			}
			if !strings.Contains(messages[0], tc.want) {
				t.Fatalf("message %q does not contain %q", messages[0], tc.want)
			}
		})
	}
}

func TestUnboundedResourceStaysQuiet(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			// The corpus's own ip_triage.mut.
			"a /29",
			`putln(cidr_hosts("192.168.1.0/29"));`,
		},
		{
			// Exactly the largest cidr_hosts will expand.
			"twenty host bits",
			`let hosts = cidr_hosts("10.0.0.0/12");`,
		},
		{
			"a computed CIDR",
			`let hosts = cidr_hosts(scope);`,
		},
		{
			// Also a guaranteed runtime error, and also not this rule's
			// subject.
			"a CIDR that does not parse",
			`let hosts = cidr_hosts("not a cidr");`,
		},
		{
			"a small range",
			`for (n in range(1, 5)) { putln(n); };`,
		},
		{
			// Exactly the longest range will return.
			"a range of exactly the cap",
			`let all = range(0, 10000000);`,
		},
		{
			"a stepped range brought back under the cap",
			`let all = range(0, 60000000, 10);`,
		},
		{
			"a range with a computed bound",
			`let all = range(0, count);`,
		},
		{
			"a range that steps away from its bound",
			`let all = range(0, 20000000, -1);`,
		},
		{
			// range: step must not be zero is the builtin's own complaint and
			// says nothing about size.
			"a zero step",
			`let all = range(0, 20000000, 0);`,
		},
		{
			"a shadowed builtin",
			`let cidr_hosts = fn(c) { return []; };
let hosts = cidr_hosts("10.0.0.0/8");`,
		},
		{
			// Two bindings mean the name has no single value to read.
			"a CIDR rebound before the call",
			`let scope = "10.0.0.0/8";
let scope = "10.0.0.0/29";
let hosts = cidr_hosts(scope);`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if messages := unboundedMessages(t, tc.src); len(messages) != 0 {
				t.Fatalf("want silence, got %v", messages)
			}
		})
	}
}

// The rule's two numbers are the builtins' own. If either implementation moves
// its cap, the thresholds here are wrong and the rule starts lying -- in the
// worse direction, reporting a call that now works.
func TestUnboundedResourceThresholdsMatchTheBuiltins(t *testing.T) {
	if maxRangeLength != 10_000_000 {
		t.Fatalf("maxRangeLength = %d; Range in builtin/collections_builtins.go caps at 10_000_000", maxRangeLength)
	}
	if maxCIDRHostBits != 20 {
		t.Fatalf("maxCIDRHostBits = %d; CIDRHosts in builtin/ioc_builtins.go caps at 20", maxCIDRHostBits)
	}
}

func TestUnboundedResourceCanBeTurnedOff(t *testing.T) {
	src := `let hosts = cidr_hosts("10.0.0.0/8");`

	config := DefaultLintConfig()
	config.UnboundedResource = LintSeverityOff

	snapshot := New().Analyze(src)
	for _, d := range Diagnostics(snapshot, config) {
		if strings.Contains(d.Message, "raises at run time") {
			t.Fatalf("rule is off but still reported: %s", d.Message)
		}
	}
}
