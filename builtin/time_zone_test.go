package builtin

import (
	"strings"
	"testing"
	"time"

	"mutant/object"
)

// M26-BLT-003. time_parse handed value and layout to time.Parse, which resolves
// a zone abbreviation -- the MST layout verb -- only when that abbreviation
// belongs to the host's own zone. For any other abbreviation Go keeps the name,
// uses offset 0, and returns no error. So "2024-07-01 10:00 PDT" was the right
// instant on a Los Angeles host and seven hours wrong on a UTC or Kolkata one,
// and the two could not be told apart by a program or by a person reading the
// output.
//
// time.FixedZone stands in for a host zone throughout, which keeps these tests
// off the zoneinfo database: Windows ships none, and importing time/tzdata to
// get one would put 450 KiB of zone table in every binary that links builtin.
//
// time.Local is process-wide, so nothing here calls t.Parallel.

const (
	zoneAbbrevLayout = "2006-01-02 15:04 MST"
	zoneAbbrevValue  = "2024-07-01 10:00 PDT"
)

// hostZones are three hosts that disagree about what PDT and IST mean: one that
// knows neither, one whose own zone is PDT, and one whose own zone is IST.
var hostZones = []struct {
	name   string
	offset int
}{
	{"UTC", 0},
	{"PDT", -7 * 3600},
	{"IST", 5*3600 + 1800},
}

func withHostZone(t *testing.T, name string, offset int) {
	t.Helper()
	saved := time.Local
	t.Cleanup(func() { time.Local = saved })
	time.Local = time.FixedZone(name, offset)
}

// TestTimeParseGivesTheSameAnswerOnEveryHost is the row itself: one timestamp,
// three hosts, one answer. The answer is a refusal, and that is the point --
// what must not happen is two different instants.
func TestTimeParseGivesTheSameAnswerOnEveryHost(t *testing.T) {
	type outcome struct {
		host    string
		unix    int64
		message string
	}

	seen := make([]outcome, 0, len(hostZones))
	for _, host := range hostZones {
		t.Run(host.name, func(t *testing.T) {
			withHostZone(t, host.name, host.offset)

			result, errObj := unwrapPair(t, TimeParse(stringObj(zoneAbbrevValue), stringObj(zoneAbbrevLayout)))
			got := outcome{host: host.name}
			if errObj != nil {
				got.message = errObj.Message
			} else {
				number, ok := result.(*object.Integer)
				if !ok {
					t.Fatalf("time_parse returned no error and no integer: %T", result)
				}
				got.unix = number.Value
			}
			seen = append(seen, got)
		})
	}

	if len(seen) != len(hostZones) {
		t.Fatalf("only %d of %d hosts ran", len(seen), len(hostZones))
	}
	for _, got := range seen[1:] {
		if got.unix != seen[0].unix || got.message != seen[0].message {
			t.Errorf("the same timestamp parses differently depending on the host zone:\n"+
				"  %s: unix=%d err=%q\n  %s: unix=%d err=%q",
				seen[0].host, seen[0].unix, seen[0].message,
				got.host, got.unix, got.message)
		}
	}
}

// TestTimeParseRefusesAZoneItCannotResolve states which way the tie is broken,
// and that the refusal says enough to act on. Reading an unresolvable
// abbreviation as +0000 is the silent wrong answer; a lookup table would be a
// guess, because an abbreviation is genuinely ambiguous.
func TestTimeParseRefusesAZoneItCannotResolve(t *testing.T) {
	withHostZone(t, "UTC", 0)

	result, errObj := unwrapPair(t, TimeParse(stringObj(zoneAbbrevValue), stringObj(zoneAbbrevLayout)))
	if errObj == nil {
		t.Fatalf("time_parse accepted an unresolvable zone abbreviation and returned %v", result)
	}
	for _, want := range []string{"PDT", "-0700"} {
		if !strings.Contains(errObj.Message, want) {
			t.Errorf("the refusal does not mention %q, so it does not say what to do:\n%s",
				want, errObj.Message)
		}
	}
	if result != nil && result.Type() != object.NULL_OBJ {
		t.Errorf("a refusal must not also return a timestamp; got %s", result.Inspect())
	}
}

// TestTimeParseStillTakesTheLayoutsThatCarryAnOffset is the other half of the
// contract, and the half that keeps this a bug fix rather than a removal. Every
// layout here states its offset or has no zone at all, so none of them depends
// on the host -- and each must give the same instant on all three hosts.
func TestTimeParseStillTakesTheLayoutsThatCarryAnOffset(t *testing.T) {
	cases := []struct {
		name   string
		layout string
		value  string
		want   int64
	}{
		{"no zone element", "2006-01-02 15:04", "2024-07-01 10:00", 1719828000},
		{"numeric offset", "2006-01-02 15:04 -0700", "2024-07-01 10:00 -0700", 1719853200},
		{"numeric zero offset", "2006-01-02 15:04 -0700", "2024-07-01 10:00 +0000", 1719828000},
		{"RFC3339 with Z", time.RFC3339, "2024-07-01T10:00:00Z", 1719828000},
		{"RFC3339 with an offset", time.RFC3339, "2024-07-01T10:00:00-07:00", 1719853200},
		{"UTC named", zoneAbbrevLayout, "2024-07-01 10:00 UTC", 1719828000},
		{"GMT named", zoneAbbrevLayout, "2024-07-01 10:00 GMT", 1719828000},
		{"an abbreviation beside its offset", "2006-01-02 15:04 MST-0700",
			"2024-07-01 10:00 PDT-0700", 1719853200},
		// docs/COOKBOOK.md's own layout: a literal Z, not the Z07:00 verb.
		{"the cookbook's literal Z", "2006-01-02T15:04:05Z", "2026-03-14T02:11:44Z", 1773454304},
	}

	for _, c := range cases {
		for _, host := range hostZones {
			t.Run(c.name+" on "+host.name, func(t *testing.T) {
				withHostZone(t, host.name, host.offset)

				result, errObj := unwrapPair(t, TimeParse(stringObj(c.value), stringObj(c.layout)))
				if errObj != nil {
					t.Fatalf("time_parse refused a layout that states its own offset: %s", errObj.Message)
				}
				number, ok := result.(*object.Integer)
				if !ok {
					t.Fatalf("time_parse returned %T, want INTEGER", result)
				}
				if number.Value != c.want {
					t.Errorf("parsed to %d, want %d", number.Value, c.want)
				}
			})
		}
	}
}

// TestTimeParseAndTimeFormatStillRoundTrip guards the pair the rest of the
// language uses, which carries no zone at all and so must be untouched.
func TestTimeParseAndTimeFormatStillRoundTrip(t *testing.T) {
	withHostZone(t, "IST", 5*3600+1800)

	const layout = "2006-01-02 15:04:05"
	const unix = int64(1_700_000_000)

	formatted, ok := TimeFormat(intObj(unix), stringObj(layout)).(*object.String)
	if !ok {
		t.Fatal("time_format did not return a STRING")
	}
	result, errObj := unwrapPair(t, TimeParse(stringObj(formatted.Value), stringObj(layout)))
	if errObj != nil {
		t.Fatalf("time_parse: %s", errObj.Message)
	}
	number, ok := result.(*object.Integer)
	if !ok {
		t.Fatalf("time_parse returned %T, want INTEGER", result)
	}
	if number.Value != unix {
		t.Errorf("the round trip moved the instant: %d, want %d", number.Value, unix)
	}
}
