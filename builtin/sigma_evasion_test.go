package builtin

import (
	"fmt"
	"strings"
	"testing"

	"mutant/object"
)

// Four rows, one defect wearing four hats: a Sigma rule that reports a clean
// no-match while the thing it was written to catch is sitting in the event.
// Most of these tests fail at a812eee -- the engine answers where it should
// refuse, or answers about less of the event than the rule asked about. Four
// do not, and each one says so in the comment above it: they pin behaviour the
// fix must NOT change, and a kit measured only red-to-green has no guard
// against its own fix overreaching.

// --- M26-ART-016: |windash --------------------------------------------------

// sigmaWindashRule is the shape a SigmaHQ process_creation rule writes.
func sigmaWindashRule(value string) string {
	return sigmaRuleFor("    CommandLine|windash|contains: '" + value + "'\n")
}

// The specification calls windash a permutation, and the reason is this: an
// attacker does not pick one dash and use it twice.
func TestWindashCatchesAMixedDashCommandLine(t *testing.T) {
	rule := sigmaParseRule(t, sigmaWindashRule(" -nop -enc "))
	for _, command := range []string{
		"pwsh -nop -enc AAAA",
		"pwsh -nop /enc AAAA",
		"pwsh /nop -enc AAAA",
		"pwsh /nop /enc AAAA",
		"pwsh \u2013nop \u2014enc AAAA",
		"pwsh -nop \u2015enc AAAA",
	} {
		event := sigmaEvent(t, map[string]object.Object{"CommandLine": stringObj(command)})
		if !sigmaBool(t, sigmaMatched(t, rule, event), "matched") {
			t.Errorf("%q did not match ' -nop -enc ' under |windash", command)
		}
	}
}

// The five characters are interchangeable, which is symmetric: a rule written
// with a slash has to catch the dash as well.
func TestWindashCatchesADashWhereTheRuleWroteASlash(t *testing.T) {
	rule := sigmaParseRule(t, sigmaWindashRule(" /c "))
	for _, command := range []string{"cmd /c whoami", "cmd -c whoami", "cmd \u2013c whoami"} {
		event := sigmaEvent(t, map[string]object.Object{"CommandLine": stringObj(command)})
		if !sigmaBool(t, sigmaMatched(t, rule, event), "matched") {
			t.Errorf("%q did not match ' /c ' under |windash", command)
		}
	}
}

func TestWindashPermutesEveryPositionIndependently(t *testing.T) {
	got, err := sigmaWindash(" -nop -enc ")
	if err != nil {
		t.Fatalf("sigmaWindash: %s", err)
	}
	if len(got) != 25 {
		t.Fatalf("expanded into %d spellings, want 25: five characters over two switch positions", len(got))
	}
	seen := map[string]bool{}
	for _, variant := range got {
		if seen[variant] {
			t.Errorf("%q came back twice", variant)
		}
		seen[variant] = true
	}
	for _, want := range []string{" -nop -enc ", " -nop /enc ", " /nop -enc ", " \u2013nop \u2015enc "} {
		if !seen[want] {
			t.Errorf("%q is not among the spellings", want)
		}
	}
}

// A dash between two word characters is part of the word. Expanding it would
// say that foo-bar.exe and foo/bar.exe are the same file.
func TestWindashLeavesADashInsideAWordAlone(t *testing.T) {
	got, err := sigmaWindash("2026-10-07 foo-bar.exe")
	if err != nil {
		t.Fatalf("sigmaWindash: %s", err)
	}
	if len(got) != 1 || got[0] != "2026-10-07 foo-bar.exe" {
		t.Fatalf("expanded a dash between two word characters: %q", got)
	}
}

// Four switch positions is 625 spellings and compiles. Five is 3125 and is
// refused by name, because a rule compiler that quietly stops expanding is the
// evasion this expansion exists to close.
func TestWindashRefusesAValueItWouldHaveToExpandTooFar(t *testing.T) {
	if _, errObj := unwrapPairNoFatal(SigmaParse(stringObj(sigmaWindashRule(" -a -b -c -d ")))); errObj != nil {
		t.Fatalf("four switch positions should compile: %s", errObj.Message)
	}
	_, errObj := unwrapPairNoFatal(SigmaParse(stringObj(sigmaWindashRule(" -a -b -c -d -e "))))
	if errObj == nil {
		t.Fatalf("sigma_parse accepted a |windash value it cannot expand")
	}
	for _, want := range []string{"switch positions", "625"} {
		if !strings.Contains(errObj.Message, want) {
			t.Errorf("error %q does not name %q", errObj.Message, want)
		}
	}
}

// --- M26-ART-017: `them` and the underscore ---------------------------------

// sigmaThemRule defines one ordinary search and one underscore-prefixed one,
// which is the arrangement the underscore convention exists for.
func sigmaThemRule(condition string) string {
	return fmt.Sprintf("title: t\ndetection:\n  selection:\n    EventID: 1\n"+
		"  _helper:\n    Channel: 'Security'\n  condition: %s\n", condition)
}

func TestAllOfThemSkipsAnUnderscoreIdentifier(t *testing.T) {
	rule := sigmaParseRule(t, sigmaThemRule("all of them"))
	event := sigmaEvent(t, map[string]object.Object{"EventID": intObj(1)})
	if !sigmaBool(t, sigmaMatched(t, rule, event), "matched") {
		t.Fatalf("`all of them` required `_helper`, which `them` does not cover")
	}
}

func TestOneOfThemIsNotSatisfiedByAnUnderscoreIdentifier(t *testing.T) {
	rule := sigmaParseRule(t, sigmaThemRule("1 of them"))
	event := sigmaEvent(t, map[string]object.Object{"Channel": stringObj("Security")})
	if sigmaBool(t, sigmaMatched(t, rule, event), "matched") {
		t.Fatalf("`1 of them` fired on `_helper` alone")
	}
}

// PASSES AT a812eee BY DESIGN, both of these. The exclusion is `them`'s and
// nothing else's: an underscore identifier is still reachable by name and still
// covered by a pattern that matches it.
func TestAnUnderscoreIdentifierIsStillUsableByName(t *testing.T) {
	rule := sigmaParseRule(t, sigmaThemRule("_helper"))
	event := sigmaEvent(t, map[string]object.Object{"Channel": stringObj("Security")})
	if !sigmaBool(t, sigmaMatched(t, rule, event), "matched") {
		t.Fatalf("a condition naming `_helper` outright did not reach it")
	}
}

func TestAnUnderscoreIdentifierIsStillCoveredByAPattern(t *testing.T) {
	rule := sigmaParseRule(t, sigmaThemRule("all of _h*"))
	event := sigmaEvent(t, map[string]object.Object{"Channel": stringObj("Security")})
	if !sigmaBool(t, sigmaMatched(t, rule, event), "matched") {
		t.Fatalf("`all of _h*` did not cover `_helper`")
	}
}

func TestThemRefusesWhenEveryIdentifierIsUnderscored(t *testing.T) {
	rule := "title: t\ndetection:\n  _only:\n    EventID: 1\n  condition: all of them\n"
	_, errObj := unwrapPairNoFatal(SigmaParse(stringObj(rule)))
	if errObj == nil {
		t.Fatalf("sigma_parse accepted `all of them` over nothing it covers")
	}
	if !strings.Contains(errObj.Message, "starts with an underscore") {
		t.Errorf("error %q does not say why", errObj.Message)
	}
}

// `N of them` counts hits among the identifiers `them` covers, which is fewer
// than the rule defines as soon as one of them is underscored. Asking for more
// than that is a rule that is silent forever, and it is a compile-time fact.
func TestNOfThemRefusesMoreThanThemCovers(t *testing.T) {
	_, errObj := unwrapPairNoFatal(SigmaParse(stringObj(sigmaThemRule("2 of them"))))
	if errObj == nil {
		t.Fatalf("sigma_parse accepted `2 of them` where `them` covers one search")
	}
	for _, want := range []string{"2 of", "them", "selection", "no event can satisfy"} {
		if !strings.Contains(errObj.Message, want) {
			t.Errorf("error %q does not name %q", errObj.Message, want)
		}
	}
}

// The test is on the resolved set and does not care how it resolved, so one
// refusal covers the pattern direction too. `2 of selection*` over one
// `selection` compiled and then matched nothing at a812eee as well.
func TestNOfAPatternRefusesMoreThanItCovers(t *testing.T) {
	rule := "title: t\ndetection:\n  selection:\n    EventID: 1\n  condition: 2 of selection*\n"
	_, errObj := unwrapPairNoFatal(SigmaParse(stringObj(rule)))
	if errObj == nil {
		t.Fatalf("sigma_parse accepted `2 of selection*` over one identifier")
	}
	if !strings.Contains(errObj.Message, "no event can satisfy") {
		t.Errorf("error %q does not say why", errObj.Message)
	}
}

// PASSES AT a812eee BY DESIGN. The refusal above must not reach a count its
// target can reach: `2 of them` over two eligible searches is satisfiable, and
// has to keep compiling and keep firing.
func TestNOfThemStillCompilesWhenThemCoversEnough(t *testing.T) {
	rule := sigmaParseRule(t, "title: t\ndetection:\n  selection:\n    EventID: 1\n"+
		"  second:\n    Channel: 'Security'\n  _helper:\n    User: 'jdoe'\n  condition: 2 of them\n")
	both := sigmaEvent(t, map[string]object.Object{"EventID": intObj(1), "Channel": stringObj("Security")})
	if !sigmaBool(t, sigmaMatched(t, rule, both), "matched") {
		t.Fatalf("`2 of them` over two eligible searches did not fire on an event satisfying both")
	}
	one := sigmaEvent(t, map[string]object.Object{"EventID": intObj(1)})
	if sigmaBool(t, sigmaMatched(t, rule, one), "matched") {
		t.Fatalf("`2 of them` fired on one search")
	}
}

// --- M26-ART-018: searches that are not questions ---------------------------

func TestSigmaRefusesASearchThatIsNotAQuestion(t *testing.T) {
	tests := []struct{ name, rule, want string }{
		{
			"empty mapping",
			"title: t\ndetection:\n  selection: {}\n  condition: selection\n",
			"empty mapping",
		},
		{
			"empty mapping inside a list",
			"title: t\ndetection:\n  selection:\n    - {}\n  condition: selection\n",
			"empty mapping",
		},
		{
			"empty value list under |all",
			"title: t\ndetection:\n  selection:\n    Image|all: []\n  condition: selection\n",
			"empty value list",
		},
		{
			"empty value list",
			"title: t\ndetection:\n  selection:\n    Image: []\n  condition: selection\n",
			"empty value list",
		},
		{
			"null inside a value list",
			"title: t\ndetection:\n  selection:\n    Image: ['x', null]\n  condition: selection\n",
			"null",
		},
		{
			"null keyword",
			"title: t\ndetection:\n  keywords:\n    - x\n    - null\n  condition: keywords\n",
			"null",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errObj := unwrapPairNoFatal(SigmaParse(stringObj(tt.rule)))
			if errObj == nil {
				t.Fatalf("sigma_parse accepted a search that tests nothing")
			}
			if !strings.Contains(errObj.Message, tt.want) {
				t.Errorf("error %q does not name %q", errObj.Message, tt.want)
			}
		})
	}
}

// PASSES AT a812eee BY DESIGN. The refusals above must not reach the one
// spelling of null that does mean something: a scalar null asks whether the
// field is absent.
func TestAScalarNullStillAsksWhetherTheFieldIsAbsent(t *testing.T) {
	rule := sigmaParseRule(t, "title: t\ndetection:\n  selection:\n    Image: null\n  condition: selection\n")
	absent := sigmaEvent(t, map[string]object.Object{"User": stringObj("jdoe")})
	if !sigmaBool(t, sigmaMatched(t, rule, absent), "matched") {
		t.Fatalf("`Image: null` stopped meaning absent")
	}
	present := sigmaEvent(t, map[string]object.Object{"Image": stringObj("cmd.exe")})
	if sigmaBool(t, sigmaMatched(t, rule, present), "matched") {
		t.Fatalf("`Image: null` matched an event that carried the field")
	}
}

// --- M26-LIM-001: how deep a keyword search reads ---------------------------

const sigmaKeywordRule = "title: t\ndetection:\n  keywords:\n    - mimikatz\n  condition: keywords\n"

// sigmaNestedEvent buries one value under `levels` nested hashes, so the value
// sits at depth `levels` in the walk a keyword search does.
func sigmaNestedEvent(t *testing.T, levels int, leaf string) *object.Hash {
	t.Helper()
	current := object.Object(stringObj(leaf))
	for i := 0; i < levels; i++ {
		current = makeHashObject(map[string]object.Object{"n": current})
	}
	hash, ok := current.(*object.Hash)
	if !ok {
		t.Fatalf("nested event is %T, want *object.Hash", current)
	}
	return hash
}

// 25 is the first depth the old bound of 24 dropped, and dropped in silence.
func TestAKeywordSearchReadsTheWholeEventAParserCanBuild(t *testing.T) {
	rule := sigmaParseRule(t, sigmaKeywordRule)
	for _, levels := range []int{1, 24, 25, 100, sigmaKeywordMaxDepth} {
		event := sigmaNestedEvent(t, levels, "ran mimikatz")
		if !sigmaBool(t, sigmaMatched(t, rule, event), "matched") {
			t.Errorf("a keyword %d levels down was not found", levels)
		}
	}
}

func TestAKeywordSearchRefusesAnEventItCannotReadWhole(t *testing.T) {
	rule := sigmaParseRule(t, sigmaKeywordRule)
	event := sigmaNestedEvent(t, sigmaKeywordMaxDepth+1, "ran mimikatz")
	_, errObj := unwrapPairNoFatal(SigmaMatch(rule, event))
	if errObj == nil {
		t.Fatalf("sigma_match reported an answer about an event it could not read")
	}
	if !strings.Contains(errObj.Message, "nests deeper than") {
		t.Errorf("error %q does not say what happened", errObj.Message)
	}
}

// The refusal is scoped to the search that walks. A rule that only looks up
// fields never reads the deep part of the event and must still answer.
func TestARuleWithNoKeywordSearchStillAnswersAboutADeepEvent(t *testing.T) {
	rule := sigmaParseRule(t, sigmaRuleFor("    Image|endswith: '\\cmd.exe'\n"))
	event := sigmaNestedEvent(t, sigmaKeywordMaxDepth+200, "ran mimikatz")
	if sigmaBool(t, sigmaMatched(t, rule, event), "matched") {
		t.Fatalf("matched an event carrying no Image")
	}
}

func TestSigmaScanNamesTheEventItCouldNotRead(t *testing.T) {
	events := &object.Array{Elements: []object.Object{
		sigmaEvent(t, map[string]object.Object{"CommandLine": stringObj("notepad.exe")}),
		sigmaNestedEvent(t, sigmaKeywordMaxDepth+1, "ran mimikatz"),
	}}
	_, errObj := unwrapPairNoFatal(SigmaScan(stringObj(sigmaKeywordRule), events))
	if errObj == nil {
		t.Fatalf("sigma_scan reported a scan over a timeline it could not read")
	}
	for _, want := range []string{"event 1", "nests deeper than"} {
		if !strings.Contains(errObj.Message, want) {
			t.Errorf("error %q does not name %q", errObj.Message, want)
		}
	}
}

// The bound is the bound the decoders that convert through nativeToObject
// enforce -- yaml_parse, toml_parse, cbor_parse, msgpack_parse -- so an event
// one of those built is searched whole. It is NOT a ceiling on what an event
// can be: json_parse and ndjson_parse convert through jsonValueToObject, which
// takes no depth argument at all, so a 257-level JSON document reaches the
// refusal above from two lines of Mutant. That is why it is a refusal.
func TestTheKeywordDepthIsTheDepthTheParsersEnforce(t *testing.T) {
	if sigmaKeywordMaxDepth != maxNativeDepth {
		t.Fatalf("sigmaKeywordMaxDepth is %d and maxNativeDepth is %d: an event a parser accepts would be searched in part",
			sigmaKeywordMaxDepth, maxNativeDepth)
	}
}
