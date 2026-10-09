package builtin

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"mutant/object"
)

// Sigma rules are YAML. This file turns one into something that can be asked a
// question about an event, and says so out loud when it cannot.
//
// One rule shapes everything here: a construct this engine does not implement
// is a compile error, never a silent non-match. A detection rule that quietly
// never fires is worse than no rule at all -- on a coverage report it reads as
// a rule you have, and in the evidence it is a blind spot. So aggregations,
// `near`, the backend-specific `|expand` placeholder and any modifier not in
// the table below are all refused by name, and a condition that names a search
// identifier the detection block does not define is refused too.

// sigmaRule is a compiled rule: the metadata a report needs, the searches, and
// the condition as an evaluable tree.
type sigmaRule struct {
	title          string
	id             string
	status         string
	description    string
	level          string
	author         string
	logsource      map[string]string
	tags           []string
	falsepositives []string
	references     []string
	condition      string
	cond           sigmaNode
	searches       map[string]*sigmaSearch
	names          []string // search identifiers, in document order
	fields         []string // every field the rule reads, sorted, deduplicated
}

// sigmaSearch is one search identifier. It is either a list of keywords --
// matched against every value in the event, wherever it sits -- or one or more
// field groups OR-ed together, each group a set of field tests that all hold.
type sigmaSearch struct {
	name     string
	keywords []sigmaMatcher
	groups   []sigmaGroup
}

type sigmaGroup struct {
	fields []sigmaField
}

// sigmaField is one `Field|modifiers: value` line. Its matchers are OR-ed
// unless |all was written, which is the whole point of that modifier.
type sigmaField struct {
	name     string   // as written, modifiers stripped
	path     []string // the name split on dots, for nested lookup
	all      bool
	matchers []sigmaMatcher
}

type sigmaMatchKind int

const (
	sigmaMatchPattern sigmaMatchKind = iota
	sigmaMatchCIDR
	sigmaMatchNumber
	sigmaMatchNull
	sigmaMatchExists
	sigmaMatchFieldRef
)

// sigmaMatcher is one value test, already compiled. Patterns arrive as regexps
// whether they were written as Sigma wildcards or as a `|re` regular
// expression, so there is one code path at match time.
type sigmaMatcher struct {
	kind   sigmaMatchKind
	re     *regexp.Regexp
	prefix netip.Prefix
	number float64
	op     string   // eq, lt, lte, gt, gte -- sigmaMatchNumber only
	want   bool     // sigmaMatchExists only
	ref    []string // sigmaMatchFieldRef only
	text   string   // the value as written, for error messages
}

// --- modifier tables -------------------------------------------------------

// sigmaTransformMods rewrite the value before it is compared. They apply in the
// order they were written, which is why `|utf16le|base64offset|contains` means
// something different from the same three in any other order.
var sigmaTransformMods = map[string]bool{
	"base64": true, "base64offset": true,
	"utf16": true, "utf16le": true, "utf16be": true, "wide": true,
	"windash": true,
}

// sigmaCompareMods choose how the value is compared. At most one may be given.
var sigmaCompareMods = map[string]bool{
	"contains": true, "startswith": true, "endswith": true,
	"re": true, "cidr": true, "exists": true, "fieldref": true,
	"lt": true, "lte": true, "gt": true, "gte": true,
}

// sigmaFlagMods change how a comparison behaves without choosing one.
var sigmaFlagMods = map[string]bool{
	"all": true, "cased": true,
	"i": true, "m": true, "s": true, // sub-modifiers of |re
}

// --- compiling a rule ------------------------------------------------------

// compileSigmaRule builds a rule from a YAML document already decoded into Go
// natives. Every refusal names the construct, because "this rule did not
// compile" is not a finding an analyst can act on.
func compileSigmaRule(doc any) (*sigmaRule, error) {
	root, ok := doc.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("a rule is a YAML mapping, got %s", sigmaTypeName(doc))
	}
	if _, present := root["action"]; present {
		return nil, fmt.Errorf("rule collections (`action: global`/`repeat`) are not supported: split the collection into standalone rules first")
	}
	rule := &sigmaRule{
		title:       sigmaString(root["title"]),
		id:          sigmaString(root["id"]),
		status:      sigmaString(root["status"]),
		description: sigmaString(root["description"]),
		level:       strings.ToLower(sigmaString(root["level"])),
		author:      sigmaString(root["author"]),
		logsource:   map[string]string{},
		searches:    map[string]*sigmaSearch{},
	}
	if rule.title == "" {
		return nil, fmt.Errorf("rule has no title")
	}
	if ls, ok := root["logsource"].(map[string]any); ok {
		for key, value := range ls {
			rule.logsource[key] = sigmaString(value)
		}
	}
	rule.tags = sigmaStringList(root["tags"])
	rule.falsepositives = sigmaStringList(root["falsepositives"])
	rule.references = sigmaStringList(root["references"])

	detection, ok := root["detection"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("rule %q has no detection block", rule.title)
	}
	if _, present := detection["timeframe"]; present {
		return nil, fmt.Errorf("rule %q uses `timeframe`, which counts events over a window: this engine answers about one event at a time and will not pretend otherwise", rule.title)
	}

	rawCondition, present := detection["condition"]
	if !present {
		return nil, fmt.Errorf("rule %q has a detection block with no condition", rule.title)
	}
	// A list condition is the spec's shorthand for OR between the entries.
	conditions := sigmaStringList(rawCondition)
	if len(conditions) == 0 {
		return nil, fmt.Errorf("rule %q has an empty condition", rule.title)
	}
	if len(conditions) == 1 {
		rule.condition = conditions[0]
	} else {
		parts := make([]string, len(conditions))
		for i, c := range conditions {
			parts[i] = "(" + c + ")"
		}
		rule.condition = strings.Join(parts, " or ")
	}

	// Search identifiers are compiled in sorted order so that `fields` and
	// `searches` come out the same for the same rule every time -- a report
	// whose field list reorders between runs is a report nobody can diff.
	names := make([]string, 0, len(detection))
	for key := range detection {
		if key == "condition" || key == "timeframe" {
			continue
		}
		names = append(names, key)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, fmt.Errorf("rule %q defines no search identifiers", rule.title)
	}

	seenFields := map[string]bool{}
	for _, name := range names {
		search, err := compileSigmaSearch(name, detection[name])
		if err != nil {
			return nil, fmt.Errorf("rule %q, search %q: %s", rule.title, name, err)
		}
		rule.searches[name] = search
		rule.names = append(rule.names, name)
		for _, group := range search.groups {
			for _, field := range group.fields {
				if !seenFields[field.name] {
					seenFields[field.name] = true
					rule.fields = append(rule.fields, field.name)
				}
			}
		}
	}
	sort.Strings(rule.fields)

	node, err := parseSigmaCondition(rule.condition, rule.names)
	if err != nil {
		return nil, fmt.Errorf("rule %q, condition %q: %s", rule.title, rule.condition, err)
	}
	rule.cond = node
	return rule, nil
}

// compileSigmaSearch handles the three shapes a search identifier takes: a
// mapping of field tests, a list of mappings (OR-ed), or a list of keywords.
func compileSigmaSearch(name string, raw any) (*sigmaSearch, error) {
	search := &sigmaSearch{name: name}
	switch value := raw.(type) {
	case map[string]any:
		group, err := compileSigmaGroup(value)
		if err != nil {
			return nil, err
		}
		search.groups = append(search.groups, group)
	case []any:
		if len(value) == 0 {
			return nil, fmt.Errorf("is an empty list, which would match everything or nothing depending on the backend")
		}
		for _, entry := range value {
			if mapping, ok := entry.(map[string]any); ok {
				group, err := compileSigmaGroup(mapping)
				if err != nil {
					return nil, err
				}
				search.groups = append(search.groups, group)
				continue
			}
			// A bare scalar in the list is a keyword: matched against every
			// value the event carries rather than against a named field.
			if entry == nil {
				// `null` in a keyword list flattens to "", and an empty
				// `contains` pattern matches every string there is, so the
				// search holds for every event carrying any value at all
				// (M26-ART-018).
				return nil, fmt.Errorf("has `null` in its keyword list: a null keyword compiles to the empty string, which matches every event")
			}
			texts, err := sigmaValueStrings(entry)
			if err != nil {
				return nil, err
			}
			matcher, err := compileSigmaMatchers(texts, []string{"contains"}, nil)
			if err != nil {
				return nil, err
			}
			search.keywords = append(search.keywords, matcher...)
		}
		if len(search.groups) > 0 && len(search.keywords) > 0 {
			return nil, fmt.Errorf("mixes keywords and field mappings in one list, which has no defined meaning")
		}
	default:
		return nil, fmt.Errorf("is a %s: a search is a mapping, a list of mappings, or a list of keywords", sigmaTypeName(raw))
	}
	return search, nil
}

func compileSigmaGroup(mapping map[string]any) (sigmaGroup, error) {
	group := sigmaGroup{}
	if len(mapping) == 0 {
		// A group with no field tests is the AND of nothing, which is true, so
		// `selection: {}` holds for every event there is and the rule reports a
		// hit on all of them. No rule means that, and a backend reading it the
		// other way round would make the same rule fire on nothing instead: it
		// is a rule bug either way, and this is where it can be said out loud
		// (M26-ART-018).
		return group, fmt.Errorf("has an empty mapping, which tests nothing: as written it holds for every event")
	}
	keys := make([]string, 0, len(mapping))
	for key := range mapping {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		field, err := compileSigmaField(key, mapping[key])
		if err != nil {
			return group, err
		}
		group.fields = append(group.fields, field)
	}
	return group, nil
}

func compileSigmaField(key string, raw any) (sigmaField, error) {
	parts := strings.Split(key, "|")
	name := parts[0]
	mods := parts[1:]
	field := sigmaField{name: name, path: strings.Split(name, ".")}
	if name == "" {
		return field, fmt.Errorf("a field test with no field name (%q)", key)
	}

	for _, mod := range mods {
		switch {
		case mod == "expand":
			return field, fmt.Errorf("field %q uses |expand, which substitutes a value from the backend's own configuration: there is no backend here to ask", name)
		case mod == "all":
			field.all = true
		case sigmaTransformMods[mod], sigmaCompareMods[mod], sigmaFlagMods[mod]:
			// handled in compileSigmaMatchers
		default:
			return field, fmt.Errorf("field %q uses an unknown modifier |%s", name, mod)
		}
	}

	if raw == nil {
		field.matchers = []sigmaMatcher{{kind: sigmaMatchNull, text: "null"}}
		return field, nil
	}
	values, err := sigmaValueStrings(raw)
	if err != nil {
		return field, fmt.Errorf("field %q: %s", name, err)
	}
	matchers, err := compileSigmaMatchers(values, mods, raw)
	if err != nil {
		return field, fmt.Errorf("field %q: %s", name, err)
	}
	field.matchers = matchers
	return field, nil
}

// compileSigmaMatchers runs the value through the transform modifiers in the
// order they were written, then builds one matcher per resulting value.
func compileSigmaMatchers(values []string, mods []string, raw any) ([]sigmaMatcher, error) {
	if len(values) == 0 {
		// An empty value list compiles to no matchers, and a field test with no
		// matchers is answered by arithmetic rather than by the event:
		// `Field|all: []` asks 0 == 0 and holds for everything, `Field: []`
		// asks 0 > 0 and holds for nothing. Neither is a question anybody wrote
		// (M26-ART-018).
		return nil, fmt.Errorf("has an empty value list, which tests nothing")
	}
	compare := ""
	cased := false
	reFlags := ""
	transformed := false
	for _, mod := range mods {
		switch mod {
		case "cased":
			cased = true
		case "i", "m", "s":
			reFlags += mod
		case "all":
			// a quantifier over the matchers, not a comparison
		default:
			if sigmaCompareMods[mod] {
				if compare != "" && compare != mod {
					return nil, fmt.Errorf("|%s and |%s both say how to compare; a field test can only be compared one way", compare, mod)
				}
				compare = mod
			}
		}
	}

	for _, mod := range mods {
		if !sigmaTransformMods[mod] {
			continue
		}
		next := make([]string, 0, len(values)*3)
		for _, value := range values {
			switch mod {
			case "base64":
				next = append(next, base64.StdEncoding.EncodeToString([]byte(value)))
			case "base64offset":
				next = append(next, sigmaBase64Offsets(value)...)
			case "utf16le", "wide":
				next = append(next, sigmaUTF16(value, false, false))
			case "utf16be":
				next = append(next, sigmaUTF16(value, true, false))
			case "utf16":
				next = append(next, sigmaUTF16(value, false, true))
			case "windash":
				expanded, err := sigmaWindash(value)
				if err != nil {
					return nil, err
				}
				next = append(next, expanded...)
			}
		}
		values = next
		if mod != "windash" {
			// Wildcards do not survive an encoding: `*` inside base64 output is
			// the literal character, not "anything". Everything after an
			// encoding is matched literally.
			transformed = true
		}
	}

	switch compare {
	case "exists":
		if len(values) != 1 {
			return nil, fmt.Errorf("|exists takes a single true or false")
		}
		want, err := strconv.ParseBool(values[0])
		if err != nil {
			return nil, fmt.Errorf("|exists takes true or false, got %q", values[0])
		}
		return []sigmaMatcher{{kind: sigmaMatchExists, want: want, text: values[0]}}, nil
	case "fieldref":
		out := make([]sigmaMatcher, 0, len(values))
		for _, value := range values {
			out = append(out, sigmaMatcher{kind: sigmaMatchFieldRef, ref: strings.Split(value, "."), text: value})
		}
		return out, nil
	case "cidr":
		out := make([]sigmaMatcher, 0, len(values))
		for _, value := range values {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, fmt.Errorf("|cidr value %q is not a network in CIDR notation: %s", value, err)
			}
			out = append(out, sigmaMatcher{kind: sigmaMatchCIDR, prefix: prefix, text: value})
		}
		return out, nil
	case "lt", "lte", "gt", "gte":
		out := make([]sigmaMatcher, 0, len(values))
		for _, value := range values {
			number, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return nil, fmt.Errorf("|%s value %q is not a number", compare, value)
			}
			out = append(out, sigmaMatcher{kind: sigmaMatchNumber, number: number, op: compare, text: value})
		}
		return out, nil
	case "re":
		out := make([]sigmaMatcher, 0, len(values))
		for _, value := range values {
			expr := value
			if reFlags != "" {
				expr = "(?" + reFlags + ")" + expr
			}
			re, err := regexp.Compile(expr)
			if err != nil {
				return nil, fmt.Errorf("|re value %q does not compile: %s", value, err)
			}
			out = append(out, sigmaMatcher{kind: sigmaMatchPattern, re: re, text: value})
		}
		return out, nil
	}

	// No comparison modifier: an unmodified number is compared as a number so
	// that `EventID: 1` matches an event carrying 1 or "1", and everything else
	// is a Sigma wildcard pattern.
	if compare == "" && !transformed && len(values) == 1 && sigmaIsNumeric(raw) {
		number, err := strconv.ParseFloat(values[0], 64)
		if err == nil {
			return []sigmaMatcher{{kind: sigmaMatchNumber, number: number, op: "eq", text: values[0]}}, nil
		}
	}

	out := make([]sigmaMatcher, 0, len(values))
	for _, value := range values {
		re, err := sigmaPatternRegexp(value, compare, cased, transformed)
		if err != nil {
			return nil, err
		}
		out = append(out, sigmaMatcher{kind: sigmaMatchPattern, re: re, text: value})
	}
	return out, nil
}

// sigmaPatternRegexp turns a Sigma value into a regexp. Anchoring carries the
// contains/startswith/endswith modifier, so the pattern itself never has to be
// rewritten and a value containing a `*` keeps meaning what it meant.
func sigmaPatternRegexp(value, compare string, cased, literal bool) (*regexp.Regexp, error) {
	var body string
	if literal {
		body = regexp.QuoteMeta(value)
	} else {
		var sb strings.Builder
		runes := []rune(value)
		for i := 0; i < len(runes); i++ {
			switch runes[i] {
			case '\\':
				// Only *, ? and \ are escapable. A backslash before anything
				// else is a backslash, which matters: Windows paths are full of
				// them and a rule should not have to double every one.
				if i+1 < len(runes) && (runes[i+1] == '*' || runes[i+1] == '?' || runes[i+1] == '\\') {
					sb.WriteString(regexp.QuoteMeta(string(runes[i+1])))
					i++
					continue
				}
				sb.WriteString(regexp.QuoteMeta(`\`))
			case '*':
				sb.WriteString(".*")
			case '?':
				sb.WriteString(".")
			default:
				sb.WriteString(regexp.QuoteMeta(string(runes[i])))
			}
		}
		body = sb.String()
	}

	prefix := "(?s)"
	if !cased {
		prefix = "(?is)"
	}
	switch compare {
	case "contains":
		// unanchored
	case "startswith":
		body = `\A` + body
	case "endswith":
		body = body + `\z`
	default:
		body = `\A` + body + `\z`
	}
	return regexp.Compile(prefix + body)
}

// sigmaBase64Offsets returns the three encodings a value takes when it can
// start at any of three byte offsets inside a base64 blob, which is what
// |base64offset exists for: the encoder does not know where the interesting
// bytes begin.
func sigmaBase64Offsets(value string) []string {
	starts := []int{0, 2, 3}
	ends := []int{0, -3, -2}
	out := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		padded := strings.Repeat(" ", i) + value
		encoded := base64.StdEncoding.EncodeToString([]byte(padded))
		start := starts[i]
		if start > len(encoded) {
			start = len(encoded)
		}
		end := len(encoded)
		if trim := ends[(len(value)+i)%3]; trim != 0 {
			end += trim
		}
		if end < start {
			end = start
		}
		out = append(out, encoded[start:end])
	}
	return out
}

// sigmaUTF16 encodes a value the way it sits in memory on Windows, which is how
// it sits inside a base64-encoded PowerShell -EncodedCommand.
func sigmaUTF16(value string, bigEndian, bom bool) string {
	units := utf16.Encode([]rune(value))
	buf := make([]byte, 0, len(units)*2+2)
	if bom {
		buf = append(buf, 0xFF, 0xFE)
	}
	for _, unit := range units {
		if bigEndian {
			buf = append(buf, byte(unit>>8), byte(unit))
			continue
		}
		buf = append(buf, byte(unit), byte(unit>>8))
	}
	return string(buf)
}

// sigmaWindashChars are the characters `|windash` treats as one. The Sigma
// specification names them: "Creates all possible permutations of the `-`, `/`,
// `–` (en dash), `—` (em dash), and `―` (horizontal bar) characters."
var sigmaWindashChars = []rune{'-', '/', '–', '—', '―'}

// sigmaWindashMaxVariants bounds how many spellings one `|windash` value may
// expand into.
//
// Five interchangeable characters over k switch positions is 5^k spellings, and
// every spelling becomes a compiled regexp that is then run against every event
// in the timeline. Four switch positions in one value is already more than the
// rules this engine was written against put there, and 5^5 = 3125 regexps out of
// one short string is a rule compiler being used as a denial of service. A
// value past the bound is refused by name: expanding it part of the way would
// be the same evasion this expansion exists to close, wearing the bound as
// cover.
//
// The bound is per VALUE, which is the whole of what it claims. A list of them
// multiplies it: five values of four switch positions each compile into 3125
// matchers in one field test and twenty into 12500, both measured. That is
// linear in what the rule author typed, with 625 as the constant, where 5^k out
// of one short string is not, and the line this bound is drawn on is that
// difference -- so a second cap on the field test is deliberately not added.
//
//mutant:limit count
const sigmaWindashMaxVariants = 625

// sigmaWindash expands a command-line switch into every spelling `|windash`
// says is the same switch. The specification asks for a permutation rather than
// a substitution -- "uses all possible permutation of strings in the selection"
// -- which is the difference between a rule that catches `-nop /enc` and a rule
// that catches only a command line whose dashes are all of one kind. An
// attacker writes the mixed one.
//
// A switch position is one of those characters at the start of the value or
// after a character that is not a letter, a digit or an underscore: `pwsh
// -enc`, `pwsh;/enc`, `pwsh "-enc`. A dash between two word characters belongs
// to the word -- a date, a GUID, a file name -- and expanding it would claim
// that `foo-bar.exe` and `foo/bar.exe` are the same string (M26-ART-016).
func sigmaWindash(value string) ([]string, error) {
	runes := []rune(value)
	positions := make([]int, 0, 4)
	for i, r := range runes {
		if !sigmaIsWindashChar(r) {
			continue
		}
		if i == 0 || !sigmaIsWordRune(runes[i-1]) {
			positions = append(positions, i)
		}
	}
	if len(positions) == 0 {
		return []string{value}, nil
	}

	total := 1
	for range positions {
		total *= len(sigmaWindashChars)
		if total > sigmaWindashMaxVariants {
			return nil, fmt.Errorf("|windash value %q has %d switch positions, which permute into more spellings than the %d this engine will compile: write the switches as separate values, or as separate field tests", value, len(positions), sigmaWindashMaxVariants)
		}
	}

	// Counting in base len(sigmaWindashChars) walks the permutations once each,
	// the digit at each place choosing that position's character. The value as
	// written is one of them, so nothing has to be prepended.
	out := make([]string, 0, total)
	buf := make([]rune, len(runes))
	for n := 0; n < total; n++ {
		copy(buf, runes)
		rest := n
		for _, at := range positions {
			buf[at] = sigmaWindashChars[rest%len(sigmaWindashChars)]
			rest /= len(sigmaWindashChars)
		}
		out = append(out, string(buf))
	}
	return out, nil
}

func sigmaIsWindashChar(r rune) bool {
	for _, dash := range sigmaWindashChars {
		if r == dash {
			return true
		}
	}
	return false
}

// sigmaIsWordRune is the ASCII word class, the one Go's regexp spells \w. A
// dash between two of these is part of a word rather than the start of a
// switch.
func sigmaIsWordRune(r rune) bool {
	return r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// --- the condition language ------------------------------------------------

type sigmaNode interface {
	eval(ctx *sigmaContext) bool
}

type sigmaAnd struct{ left, right sigmaNode }
type sigmaOr struct{ left, right sigmaNode }
type sigmaNot struct{ inner sigmaNode }
type sigmaRef struct{ name string }

// sigmaQuant is `N of pattern`, `all of pattern`, `1 of them`. The identifiers
// it covers are resolved when the rule compiles, not when it runs, so a pattern
// that names nothing is a compile error rather than a condition that is
// vacuously true forever.
type sigmaQuant struct {
	names []string
	count int  // how many must hold
	all   bool // all of them
}

func (n *sigmaAnd) eval(ctx *sigmaContext) bool { return n.left.eval(ctx) && n.right.eval(ctx) }
func (n *sigmaOr) eval(ctx *sigmaContext) bool  { return n.left.eval(ctx) || n.right.eval(ctx) }
func (n *sigmaNot) eval(ctx *sigmaContext) bool { return !n.inner.eval(ctx) }
func (n *sigmaRef) eval(ctx *sigmaContext) bool { return ctx.search(n.name) }

func (n *sigmaQuant) eval(ctx *sigmaContext) bool {
	hits := 0
	for _, name := range n.names {
		if ctx.search(name) {
			hits++
			if !n.all && hits >= n.count {
				return true
			}
		} else if n.all {
			return false
		}
	}
	if n.all {
		return true
	}
	return hits >= n.count
}

type sigmaToken struct {
	text string
}

func sigmaTokenize(condition string) []sigmaToken {
	tokens := make([]sigmaToken, 0, 8)
	var current strings.Builder
	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, sigmaToken{text: current.String()})
			current.Reset()
		}
	}
	for _, r := range condition {
		switch {
		case r == '(' || r == ')' || r == '|':
			flush()
			tokens = append(tokens, sigmaToken{text: string(r)})
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			flush()
		default:
			current.WriteRune(r)
		}
	}
	flush()
	return tokens
}

type sigmaParser struct {
	tokens []sigmaToken
	pos    int
	names  []string
}

func parseSigmaCondition(condition string, names []string) (sigmaNode, error) {
	parser := &sigmaParser{tokens: sigmaTokenize(condition), names: names}
	if len(parser.tokens) == 0 {
		return nil, fmt.Errorf("is empty")
	}
	for _, token := range parser.tokens {
		if token.text == "|" {
			return nil, fmt.Errorf("uses an aggregation (`|`), which counts or groups events: this engine answers about one event at a time and will not report a rule as matched when it has not evaluated the aggregation")
		}
		if strings.EqualFold(token.text, "near") {
			return nil, fmt.Errorf("uses `near`, which correlates events across a window: this engine answers about one event at a time")
		}
	}
	node, err := parser.parseOr()
	if err != nil {
		return nil, err
	}
	if parser.pos != len(parser.tokens) {
		return nil, fmt.Errorf("has trailing input at %q", parser.tokens[parser.pos].text)
	}
	return node, nil
}

func (p *sigmaParser) peek() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	return p.tokens[p.pos].text
}

func (p *sigmaParser) acceptKeyword(word string) bool {
	if strings.EqualFold(p.peek(), word) {
		p.pos++
		return true
	}
	return false
}

func (p *sigmaParser) parseOr() (sigmaNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.acceptKeyword("or") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &sigmaOr{left: left, right: right}
	}
	return left, nil
}

func (p *sigmaParser) parseAnd() (sigmaNode, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.acceptKeyword("and") {
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &sigmaAnd{left: left, right: right}
	}
	return left, nil
}

func (p *sigmaParser) parseUnary() (sigmaNode, error) {
	if p.acceptKeyword("not") {
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &sigmaNot{inner: inner}, nil
	}
	return p.parsePrimary()
}

func (p *sigmaParser) parsePrimary() (sigmaNode, error) {
	token := p.peek()
	if token == "" {
		return nil, fmt.Errorf("ends where a search identifier was expected")
	}
	if token == "(" {
		p.pos++
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("has an unclosed `(`")
		}
		p.pos++
		return inner, nil
	}
	if token == ")" {
		return nil, fmt.Errorf("has a `)` with no `(`")
	}

	// A quantifier: `all of ...`, `any of ...`, `N of ...`.
	lower := strings.ToLower(token)
	if lower == "all" || lower == "any" || sigmaIsInteger(token) {
		if p.pos+1 < len(p.tokens) && strings.EqualFold(p.tokens[p.pos+1].text, "of") {
			p.pos += 2
			target := p.peek()
			if target == "" {
				return nil, fmt.Errorf("ends after `of`")
			}
			p.pos++
			names, err := p.resolve(target)
			if err != nil {
				return nil, err
			}
			quant := &sigmaQuant{names: names}
			switch {
			case lower == "all":
				quant.all = true
			case lower == "any":
				quant.count = 1
			default:
				count, _ := strconv.Atoi(token)
				if count < 1 {
					return nil, fmt.Errorf("asks for %d of %q, which no event can fail", count, target)
				}
				// The mirror of the refusal above with the sign flipped. A
				// quantifier counts hits among the identifiers its target
				// resolved to, so `N of ...` over fewer than N of them is
				// false for every event there will ever be: a rule that is
				// silent forever, which is the defect this cluster refuses
				// rather than let an analyst read as a clean host. Both
				// halves are known here -- the count is written in the rule
				// and `names` was resolved four lines up.
				//
				// `them` is what makes it reachable without a typo, because
				// `them` covers only the identifiers that do not start with
				// an underscore (M26-ART-017): a rule defining `selection`
				// and `_helper` defines two searches and `2 of them` has one
				// to count. A pattern reaches it too -- `2 of selection*`
				// over one `selection` never matched, at a812eee either --
				// and this covers that as well, because the test is on the
				// resolved set and does not care how it resolved.
				if count > len(names) {
					return nil, fmt.Errorf("asks for %d of %q, which covers %d of this rule's search identifiers (%s), so no event can satisfy it", count, target, len(names), strings.Join(names, ", "))
				}
				quant.count = count
			}
			return quant, nil
		}
	}

	p.pos++
	for _, name := range p.names {
		if name == token {
			return &sigmaRef{name: token}, nil
		}
	}
	return nil, fmt.Errorf("names %q, which the detection block does not define", token)
}

// resolve expands `them` and `selection*` into the identifiers they cover. A
// pattern matching nothing is refused: `all of filter*` over no filters is true
// for every event ever seen, and a rule that says that did not mean to.
func (p *sigmaParser) resolve(target string) ([]string, error) {
	if strings.EqualFold(target, "them") {
		if len(p.names) == 0 {
			return nil, fmt.Errorf("says `of them` with no search identifiers defined")
		}
		// `them` is, in the specification's words, "all defined search
		// identifiers not starting with an underscore `_`". The underscore is
		// how a rule carries a search its condition names on purpose and `them`
		// must not: counting one in makes `all of them` require a search the
		// rule never asked for, which is a rule that stops firing, and makes
		// `1 of them` satisfied by that search alone, which is a rule that
		// fires on something it was not written to report (M26-ART-017).
		covered := make([]string, 0, len(p.names))
		for _, name := range p.names {
			if strings.HasPrefix(name, "_") {
				continue
			}
			covered = append(covered, name)
		}
		if len(covered) == 0 {
			return nil, fmt.Errorf("says `of them` where every search identifier the rule defines (%s) starts with an underscore, which `them` does not cover: name the searches the condition means", strings.Join(p.names, ", "))
		}
		return covered, nil
	}
	re, err := sigmaPatternRegexp(target, "", true, false)
	if err != nil {
		return nil, fmt.Errorf("has a malformed identifier pattern %q", target)
	}
	matched := make([]string, 0, len(p.names))
	for _, name := range p.names {
		if re.MatchString(name) {
			matched = append(matched, name)
		}
	}
	if len(matched) == 0 {
		return nil, fmt.Errorf("says `of %s`, which matches none of the search identifiers this rule defines (%s)", target, strings.Join(p.names, ", "))
	}
	return matched, nil
}

// --- evaluating against an event -------------------------------------------

// sigmaContext carries one event through one rule. Search results are memoized
// because `selection and not (selection and filter)` is a normal thing to write
// and evaluating a search twice for one event is work nobody asked for.
type sigmaContext struct {
	rule    *sigmaRule
	event   object.Object
	results map[string]bool
	seen    map[string]bool // fields the event actually carried
	missing map[string]bool // fields the rule read and the event did not have
	values  []string        // every string value in the event, for keywords
	walked  bool
	walkErr error // the keyword walk ran out of depth, so values is partial
}

func (ctx *sigmaContext) search(name string) bool {
	if result, ok := ctx.results[name]; ok {
		return result
	}
	search := ctx.rule.searches[name]
	result := false
	if search != nil {
		result = ctx.evalSearch(search)
	}
	ctx.results[name] = result
	return result
}

func (ctx *sigmaContext) evalSearch(search *sigmaSearch) bool {
	if len(search.keywords) > 0 {
		for _, matcher := range search.keywords {
			for _, value := range ctx.allValues() {
				if sigmaValueMatches(matcher, &object.String{Value: value}, ctx) {
					return true
				}
			}
		}
		return false
	}
	for _, group := range search.groups {
		if ctx.evalGroup(group) {
			return true
		}
	}
	return false
}

func (ctx *sigmaContext) evalGroup(group sigmaGroup) bool {
	all := true
	for _, field := range group.fields {
		if !ctx.evalField(field) {
			all = false
		}
	}
	return all
}

func (ctx *sigmaContext) evalField(field sigmaField) bool {
	value, found := sigmaLookup(ctx.event, field.name, field.path)
	if found {
		ctx.seen[field.name] = true
	} else {
		ctx.missing[field.name] = true
	}

	hits := 0
	for _, matcher := range field.matchers {
		switch matcher.kind {
		case sigmaMatchNull:
			if !found || value.Type() == object.NULL_OBJ {
				hits++
			}
			continue
		case sigmaMatchExists:
			if found == matcher.want {
				hits++
			}
			continue
		}
		if !found {
			continue
		}
		if sigmaValueMatches(matcher, value, ctx) {
			hits++
		}
	}
	if field.all {
		return hits == len(field.matchers)
	}
	return hits > 0
}

func sigmaValueMatches(matcher sigmaMatcher, value object.Object, ctx *sigmaContext) bool {
	// A field holding a list matches when any element does, which is how a rule
	// written against a scalar field keeps working when the parser records
	// several values for it.
	if array, ok := value.(*object.Array); ok {
		for _, element := range array.Elements {
			if sigmaValueMatches(matcher, element, ctx) {
				return true
			}
		}
		return false
	}

	switch matcher.kind {
	case sigmaMatchPattern:
		return matcher.re.MatchString(sigmaObjectString(value))
	case sigmaMatchNumber:
		number, ok := sigmaObjectNumber(value)
		if !ok {
			// Only equality has a sensible string fallback; asking whether
			// "SYSTEM" is less than 5 has no answer worth inventing.
			return matcher.op == "eq" && strings.EqualFold(sigmaObjectString(value), matcher.text)
		}
		switch matcher.op {
		case "eq":
			return number == matcher.number
		case "lt":
			return number < matcher.number
		case "lte":
			return number <= matcher.number
		case "gt":
			return number > matcher.number
		case "gte":
			return number >= matcher.number
		}
		return false
	case sigmaMatchCIDR:
		addr, err := netip.ParseAddr(strings.TrimSpace(sigmaObjectString(value)))
		if err != nil {
			return false
		}
		return matcher.prefix.Contains(addr)
	case sigmaMatchFieldRef:
		other, found := sigmaLookup(ctx.event, strings.Join(matcher.ref, "."), matcher.ref)
		if !found {
			return false
		}
		return strings.EqualFold(sigmaObjectString(value), sigmaObjectString(other))
	}
	return false
}

// sigmaLookup finds a field. It tries the name as written first, because a key
// can contain a dot, then walks the dotted path -- and then does both again
// inside `extra`, where events_from() keeps the source entry verbatim. That
// second pass is what lets a rule written in a source's own taxonomy
// (`Image`, `CommandLine`, `EventID`) run against a normalized Mutant event
// without a field-mapping file in between.
func sigmaLookup(event object.Object, name string, path []string) (object.Object, bool) {
	if value, ok := sigmaDescend(event, name, path); ok {
		return value, true
	}
	hash, ok := event.(*object.Hash)
	if !ok {
		return nil, false
	}
	extra := hashValueByKey(hash, "extra")
	if extra == nil {
		return nil, false
	}
	return sigmaDescend(extra, name, path)
}

func sigmaDescend(root object.Object, name string, path []string) (object.Object, bool) {
	hash, ok := root.(*object.Hash)
	if !ok {
		return nil, false
	}
	if value := hashValueByKey(hash, name); value != nil {
		return value, true
	}
	if len(path) < 2 {
		return nil, false
	}
	current := root
	for _, segment := range path {
		hash, ok := current.(*object.Hash)
		if !ok {
			return nil, false
		}
		value := hashValueByKey(hash, segment)
		if value == nil {
			return nil, false
		}
		current = value
	}
	return current, true
}

// sigmaKeywordMaxDepth bounds how deep a keyword search walks an event.
//
// A keyword search is the one search shape with no field to look up: it
// compares its value against every value the event carries, wherever that
// value sits, which means walking the whole tree. The walk needs a bound for
// the same reason every decoder in this package has one -- an event is
// evidence, and evidence is written by whoever is under investigation, so a few
// hundred bytes can describe a hundred thousand levels and the walk is
// recursive. It is maxNativeDepth because that is the bound every decoder that
// converts through nativeToObject already enforces -- yaml_parse, toml_parse,
// cbor_parse, msgpack_parse -- so an event one of those built is searched
// whole, and a keyword search that comes back empty came back empty about the
// event rather than about the part of it this function managed to read.
//
// It is NOT a ceiling on how deep an event can be, which is why this bound has
// to be a refusal and not a quiet return. json.go's jsonValueToObject takes no
// depth argument at all, so json_parse and ndjson_parse convert as deep as
// encoding/json's scanner allows: measured, 10000 levels decode and 10001 is
// refused as "exceeded max depth". A 257-level JSON document is two lines of
// Mutant away from this function, and at a812eee it got a clean no-match.
//
//mutant:limit depth
const sigmaKeywordMaxDepth = maxNativeDepth

// allValues flattens every string the event carries, once, for keyword
// searches. Keywords are the one search shape with no field to look up.
func (ctx *sigmaContext) allValues() []string {
	if ctx.walked {
		return ctx.values
	}
	ctx.walked = true
	ctx.walkErr = sigmaCollect(ctx.event, &ctx.values, 0)
	return ctx.values
}

// sigmaCollect walks the event. It returns an error rather than stopping
// quietly when it runs out of depth: a keyword search over a tree it only
// partly read answers about the part it read, and reports that as an answer
// about the event. The shape of that wrong answer is always "no match", which
// is the one answer a detection engine must never invent (M26-LIM-001).
func sigmaCollect(value object.Object, out *[]string, depth int) error {
	if value == nil {
		return nil
	}
	if depth > sigmaKeywordMaxDepth {
		return fmt.Errorf("event nests deeper than %d levels, so a keyword search cannot read all of it", sigmaKeywordMaxDepth)
	}
	switch typed := value.(type) {
	case *object.Hash:
		for _, pair := range typed.Pairs {
			if err := sigmaCollect(pair.Value, out, depth+1); err != nil {
				return err
			}
		}
	case *object.Array:
		for _, element := range typed.Elements {
			if err := sigmaCollect(element, out, depth+1); err != nil {
				return err
			}
		}
	default:
		if text := sigmaObjectString(value); text != "" {
			*out = append(*out, text)
		}
	}
	return nil
}

// matchSigmaRule answers one rule against one event, and reports which fields
// it could not find. A rule that did not match because the event never carried
// the field it reads is a different answer from a rule that looked and
// disagreed, and only one of them means "clean".
//
// It returns an error instead of an answer when it could not read the event it
// was asked about. There is one such case -- an event nesting deeper than
// sigmaKeywordMaxDepth under a keyword search -- and it is an error rather than
// a flag on the result because a flag is read only by a caller that knows to
// look for it, and what sits under this one is a false negative (M26-LIM-001).
func matchSigmaRule(rule *sigmaRule, event object.Object) (bool, []string, []string, []string, error) {
	ctx := &sigmaContext{
		rule:    rule,
		event:   event,
		results: map[string]bool{},
		seen:    map[string]bool{},
		missing: map[string]bool{},
	}
	// Every search runs before the condition does, rather than being reached
	// through it. `selection and not filter` over an event with no selection
	// would otherwise short-circuit past the filter and never look up the
	// fields it reads, so which fields came back missing would depend on the
	// shape of the boolean rather than on the evidence. The searches are
	// memoized, so the condition below costs nothing to evaluate afterwards.
	for _, name := range rule.names {
		ctx.search(name)
	}
	matched := rule.cond.eval(ctx)
	if ctx.walkErr != nil {
		// A keyword search read part of the event and then ran out of depth.
		// Whatever the condition computed above, it is not an answer about this
		// event.
		return false, nil, nil, nil, ctx.walkErr
	}

	hitNames := make([]string, 0, len(rule.names))
	for _, name := range rule.names {
		if ctx.results[name] {
			hitNames = append(hitNames, name)
		}
	}
	// A field found anywhere is not missing, even if another group looked in a
	// branch that did not have it.
	missing := make([]string, 0, len(ctx.missing))
	for name := range ctx.missing {
		if !ctx.seen[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	seen := make([]string, 0, len(ctx.seen))
	for name := range ctx.seen {
		seen = append(seen, name)
	}
	sort.Strings(seen)
	return matched, hitNames, seen, missing, nil
}

// --- small helpers ---------------------------------------------------------

func sigmaTypeName(value any) string {
	switch value.(type) {
	case nil:
		return "null"
	case map[string]any:
		return "mapping"
	case []any:
		return "list"
	case string:
		return "string"
	case bool:
		return "boolean"
	}
	return "scalar"
}

func sigmaString(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return sigmaScalarString(value)
}

func sigmaScalarString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case bool:
		return strconv.FormatBool(typed)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case uint64:
		return strconv.FormatUint(typed, 10)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case nil:
		return ""
	}
	return fmt.Sprintf("%v", value)
}

func sigmaIsNumeric(value any) bool {
	switch value.(type) {
	case int, int64, uint64, float64:
		return true
	}
	return false
}

func sigmaIsInteger(text string) bool {
	if text == "" {
		return false
	}
	for _, r := range text {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// sigmaValueStrings flattens a scalar or a list of scalars. A nested list in a
// value position has no meaning in Sigma, so it flattens rather than erroring:
// the values are still the values.
//
// A `null` inside a list is the one entry it refuses. The specification keeps
// it out -- "`null` cannot be part of a list of field values as it is its own
// type and therefore shares no type with any other value" -- and flattening it
// to "" does not merely lose it, it changes the question being asked: a scalar
// `Field: null` asks whether the field is absent, while the same word one line
// further in asked whether it held the empty string. Under |all that reads as
// "and the field is empty", which no event satisfies, so the rule goes quiet
// (M26-ART-018).
func sigmaValueStrings(value any) ([]string, error) {
	switch typed := value.(type) {
	case []any:
		out := make([]string, 0, len(typed))
		for _, entry := range typed {
			if entry == nil {
				return nil, fmt.Errorf("has `null` inside a list of values, which Sigma does not allow there: null is its own type and shares none with any other value. A null test belongs in a field test of its own")
			}
			values, err := sigmaValueStrings(entry)
			if err != nil {
				return nil, err
			}
			out = append(out, values...)
		}
		return out, nil
	default:
		return []string{sigmaScalarString(value)}, nil
	}
}

func sigmaStringList(value any) []string {
	if value == nil {
		return nil
	}
	if list, ok := value.([]any); ok {
		out := make([]string, 0, len(list))
		for _, entry := range list {
			out = append(out, sigmaScalarString(entry))
		}
		return out
	}
	return []string{sigmaScalarString(value)}
}

func sigmaObjectString(value object.Object) string {
	switch typed := value.(type) {
	case *object.String:
		return typed.Value
	case *object.Integer:
		return strconv.FormatInt(typed.Value, 10)
	case *object.Float:
		return strconv.FormatFloat(typed.Value, 'f', -1, 64)
	case *object.Boolean:
		return strconv.FormatBool(typed.Value)
	case *object.Bytes:
		return string(typed.Value)
	case nil:
		return ""
	}
	if value.Type() == object.NULL_OBJ {
		return ""
	}
	return value.Inspect()
}

func sigmaObjectNumber(value object.Object) (float64, bool) {
	switch typed := value.(type) {
	case *object.Integer:
		return float64(typed.Value), true
	case *object.Float:
		return typed.Value, true
	case *object.String:
		number, err := strconv.ParseFloat(strings.TrimSpace(typed.Value), 64)
		if err != nil {
			return 0, false
		}
		return number, true
	}
	return 0, false
}
