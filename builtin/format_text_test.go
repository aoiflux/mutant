package builtin

import (
	"strings"
	"testing"

	"mutant/object"
)

// The text formats are the ones an analyst types a path to and expects to
// simply open: a SIEM export, a Scheduled Task, a Sigma rule. These tests are
// therefore as interested in the shapes that go wrong quietly -- a BOM, a
// duplicate column, a second YAML document, an entity that expands -- as in
// the happy path, because every one of those returns a plausible wrong answer
// rather than an error unless something stops it.

func callErr(t *testing.T, fn func(...object.Object) object.Object, args ...object.Object) *object.Error {
	t.Helper()

	_, errObj := callPair(t, fn, args...)
	if errObj == nil {
		t.Fatal("call succeeded; it was expected to fail")
	}
	return errObj
}

// --- CSV ---

func TestCsvParseKeysRowsByHeader(t *testing.T) {
	rows := mustArray(t, mustCall(t, CsvParse, str("host,pid,name\nWS01,4242,evil.exe\nWS02,7,svchost.exe\n")))
	if len(rows.Elements) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows.Elements))
	}
	if got := hashStr(t, rows.Elements[0], "name"); got != "evil.exe" {
		t.Errorf("name = %q, want evil.exe", got)
	}
	if got := hashStr(t, rows.Elements[1], "host"); got != "WS02" {
		t.Errorf("host = %q, want WS02", got)
	}
}

// Excel and PowerShell's Export-Csv both write a UTF-8 BOM. Without stripping
// it the first column is named "<BOM>host" and every lookup of "host" misses
// -- silently, since a missing key is not an error.
func TestCsvParseStripsTheBOMExcelWrites(t *testing.T) {
	rows := mustArray(t, mustCall(t, CsvParse, str("\ufeffhost,pid\nWS01,4242\n")))
	if len(rows.Elements) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows.Elements))
	}
	if got := hashStr(t, rows.Elements[0], "host"); got != "WS01" {
		t.Errorf("host = %q, want WS01 (the BOM was not stripped)", got)
	}
}

// First-wins, last-wins and auto-rename each silently answer a question only
// the analyst can. Refusing is the only honest option.
func TestCsvParseRefusesDuplicateColumns(t *testing.T) {
	errObj := callErr(t, CsvParse, str("host,pid,host\nWS01,1,WS02\n"))
	if !strings.Contains(errObj.Message, "host") {
		t.Errorf("the error must name the duplicated column; got %q", errObj.Message)
	}
}

func TestCsvParseWithoutHeaderYieldsArrays(t *testing.T) {
	opts := &object.Hash{}
	setHashKey(t, opts, "header", &object.Boolean{Value: false})

	rows := mustArray(t, mustCall(t, CsvParse, str("a,b\nc,d\n"), opts))
	first := mustArray(t, rows.Elements[0])
	if len(first.Elements) != 2 || first.Elements[0].Inspect() != "a" {
		t.Fatalf("row 1 = %s, want [a, b]", first.Inspect())
	}
}

// A ragged row is real data, not corruption -- so it is read, but the surplus
// fields go somewhere nameable rather than off the end.
func TestCsvParsePutsSurplusFieldsInExtra(t *testing.T) {
	rows := mustArray(t, mustCall(t, CsvParse, str("a,b\n1,2,3,4\n")))
	extra := mustArray(t, hashField(t, rows.Elements[0], csvExtraKey))
	if len(extra.Elements) != 2 {
		t.Fatalf("_extra = %s, want two surplus fields", extra.Inspect())
	}
}

func TestCsvParseRefusesAColumnNamedExtra(t *testing.T) {
	errObj := callErr(t, CsvParse, str("a,_extra\n1,2\n"))
	if !strings.Contains(errObj.Message, csvExtraKey) {
		t.Errorf("the error must explain the collision; got %q", errObj.Message)
	}
}

// A misspelled option that parses is worse than one that fails: the program
// runs and quietly ignores what was asked for.
func TestCsvParseRefusesAnUnknownOption(t *testing.T) {
	opts := &object.Hash{}
	setHashKey(t, opts, "headers", &object.Boolean{Value: false})

	errObj := callErr(t, CsvParse, str("a\n1\n"), opts)
	if !strings.Contains(errObj.Message, "headers") {
		t.Errorf("the error must name the rejected key; got %q", errObj.Message)
	}
}

func TestCsvParseReadsTabsWhenAsked(t *testing.T) {
	opts := &object.Hash{}
	setHashKey(t, opts, "delimiter", str("\t"))

	rows := mustArray(t, mustCall(t, CsvParse, str("host\tpid\nWS01\t7\n"), opts))
	if got := hashStr(t, rows.Elements[0], "pid"); got != "7" {
		t.Errorf("pid = %q, want 7", got)
	}
}

func TestCsvStringifyRoundTrips(t *testing.T) {
	rows := mustCall(t, CsvParse, str("host,pid\nWS01,4242\nWS02,7\n"))
	text, ok := mustCall(t, CsvStringify, rows).(*object.String)
	if !ok {
		t.Fatal("csv_stringify did not return a string")
	}
	again := mustArray(t, mustCall(t, CsvParse, str(text.Value)))
	if len(again.Elements) != 2 || hashStr(t, again.Elements[1], "host") != "WS02" {
		t.Fatalf("round trip lost data: %q", text.Value)
	}
}

// The header is the union of every row's keys, so a row missing one writes an
// empty field instead of shifting its neighbours one column left.
func TestCsvStringifyUnionsColumnsAcrossRows(t *testing.T) {
	first := &object.Hash{}
	setHashKey(t, first, "a", str("1"))
	second := &object.Hash{}
	setHashKey(t, second, "b", str("2"))

	text := mustCall(t, CsvStringify, &object.Array{Elements: []object.Object{first, second}}).(*object.String)
	if !strings.HasPrefix(text.Value, "a,b\n") {
		t.Fatalf("header = %q, want the union a,b", text.Value)
	}
	if !strings.Contains(text.Value, "1,\n") || !strings.Contains(text.Value, ",2\n") {
		t.Fatalf("missing keys did not become empty fields: %q", text.Value)
	}
}

// --- XML ---

const scheduledTask = `<?xml version="1.0" encoding="UTF-16"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Actions Context="Author">
    <Exec><Command>powershell.exe</Command><Arguments>-enc SQBFAFgA</Arguments></Exec>
  </Actions>
</Task>`

func TestXmlParseBuildsANodeTree(t *testing.T) {
	root := mustCall(t, XmlParse, str(strings.Replace(scheduledTask, `encoding="UTF-16"`, `encoding="utf-8"`, 1)))
	if got := hashStr(t, root, "name"); got != "Task" {
		t.Fatalf("root = %q, want Task", got)
	}
	if got := hashStr(t, root, "namespace"); !strings.Contains(got, "microsoft.com") {
		t.Errorf("namespace = %q, want the task schema", got)
	}
	children := mustArray(t, hashField(t, root, "children"))
	if len(children.Elements) != 2 {
		t.Fatalf("root has %d children, want 2", len(children.Elements))
	}
}

func TestXmlFindWalksNamesStarsAndDoubleStars(t *testing.T) {
	root := mustCall(t, XmlParse, str(strings.Replace(scheduledTask, `encoding="UTF-16"`, `encoding="utf-8"`, 1)))

	commands := mustArray(t, mustCall(t, XmlFind, root, str("**/Command")))
	if len(commands.Elements) != 1 {
		t.Fatalf("**/Command matched %d nodes, want 1", len(commands.Elements))
	}
	if got := hashStr(t, commands.Elements[0], "text"); got != "powershell.exe" {
		t.Errorf("command text = %q", got)
	}

	triggers := mustArray(t, mustCall(t, XmlFind, root, str("Triggers/*")))
	if len(triggers.Elements) != 1 || hashStr(t, triggers.Elements[0], "name") != "LogonTrigger" {
		t.Fatalf("Triggers/* = %s", triggers.Inspect())
	}

	// ** matches at the current node too, which is what makes "**/x" find a
	// direct child rather than only a grandchild.
	actions := mustArray(t, mustCall(t, XmlFind, root, str("**/Actions")))
	if len(actions.Elements) != 1 {
		t.Fatalf("**/Actions matched %d nodes, want 1", len(actions.Elements))
	}
	attrs := hashField(t, actions.Elements[0], "attrs")
	if got := hashStr(t, attrs, "Context"); got != "Author" {
		t.Errorf("@Context = %q, want Author", got)
	}
}

// Entity expansion and external entities are the two classic XML attacks. The
// decoder is left with no entity table, so both fail at the reference instead
// of being expanded or fetched.
func TestXmlParseRefusesAnUndeclaredEntity(t *testing.T) {
	bomb := `<!DOCTYPE lol [<!ENTITY lol "ha">]><lol>&lol;</lol>`
	if errObj := callErr(t, XmlParse, str(bomb)); !strings.Contains(strings.ToLower(errObj.Message), "entity") {
		t.Errorf("error should name the entity; got %q", errObj.Message)
	}
}

// A document silently misdecoded is worse than one that will not open, so an
// unrecognised charset is named rather than guessed at.
func TestXmlParseNamesACharsetItCannotDecode(t *testing.T) {
	doc := `<?xml version="1.0" encoding="shift_jis"?><a/>`
	if errObj := callErr(t, XmlParse, str(doc)); !strings.Contains(errObj.Message, "shift_jis") {
		t.Errorf("error should name the charset; got %q", errObj.Message)
	}
}

func TestXmlParseDecodesWindows1252(t *testing.T) {
	// 0xA9 is (c) in windows-1252 and invalid on its own in UTF-8.
	doc := []byte(`<?xml version="1.0" encoding="windows-1252"?><a>`)
	doc = append(doc, 0xa9)
	doc = append(doc, []byte(`</a>`)...)

	root := mustCall(t, XmlParse, &object.Bytes{Value: doc})
	if got := hashStr(t, root, "text"); got != "©" {
		t.Errorf("text = %q, want the copyright sign", got)
	}
}

// --- NDJSON ---

func TestNdjsonParseReadsOneValuePerLine(t *testing.T) {
	values := mustArray(t, mustCall(t, NdjsonParse, str("{\"ts\":1}\n\n{\"ts\":2}\n")))
	if len(values.Elements) != 2 {
		t.Fatalf("got %d values, want 2 (blank lines are skipped)", len(values.Elements))
	}
}

// Truncating the stream at the first bad line would hide the rest of the
// evidence; naming the line lets the caller go look at it.
func TestNdjsonParseNamesTheOffendingLine(t *testing.T) {
	errObj := callErr(t, NdjsonParse, str("{\"a\":1}\n{oops\n{\"b\":2}\n"))
	if !strings.Contains(errObj.Message, "line 2") {
		t.Errorf("error should name line 2; got %q", errObj.Message)
	}
}

func TestNdjsonStringifyRoundTrips(t *testing.T) {
	values := mustCall(t, NdjsonParse, str("{\"a\":1}\n{\"a\":2}\n"))
	text := mustCall(t, NdjsonStringify, values).(*object.String)
	if !strings.HasSuffix(text.Value, "\n") {
		t.Error("output must end in a newline so it concatenates with another stream")
	}
	again := mustArray(t, mustCall(t, NdjsonParse, str(text.Value)))
	if len(again.Elements) != 2 {
		t.Fatalf("round trip produced %d values", len(again.Elements))
	}
}

// --- YAML ---

const sigmaRules = `title: Suspicious PowerShell
detection:
  selection:
    Image|endswith: '\powershell.exe'
  condition: selection
level: high
---
title: Second Rule
level: low
`

func TestYamlParseReadsOnlyTheFirstDocument(t *testing.T) {
	doc := mustCall(t, YamlParse, str(sigmaRules))
	if got := hashStr(t, doc, "title"); got != "Suspicious PowerShell" {
		t.Fatalf("title = %q", got)
	}
}

// A Sigma ruleset is one file of --- separated documents. yaml_parse returns
// the first and says nothing about the rest, which is the whole reason this
// second builtin exists.
func TestYamlParseAllReadsEveryDocument(t *testing.T) {
	docs := mustArray(t, mustCall(t, YamlParseAll, str(sigmaRules)))
	if len(docs.Elements) != 2 {
		t.Fatalf("got %d documents, want 2", len(docs.Elements))
	}
	if got := hashStr(t, docs.Elements[1], "title"); got != "Second Rule" {
		t.Errorf("second title = %q", got)
	}
}

func TestYamlStringifyRoundTrips(t *testing.T) {
	value := mustCall(t, YamlParse, str("a: 1\nb:\n  - x\n  - y\n"))
	text := mustCall(t, YamlStringify, value).(*object.String)
	again := mustCall(t, YamlParse, str(text.Value))
	if hashInt(t, again, "a") != 1 {
		t.Fatalf("round trip lost a: %q", text.Value)
	}
}

// --- TOML ---

func TestTomlParseReadsTablesAndTimes(t *testing.T) {
	value := mustCall(t, TomlParse, str("name = \"mutant\"\ncreated = 2026-09-06T12:00:00Z\n\n[build]\nstrip = true\n"))
	if got := hashStr(t, value, "name"); got != "mutant" {
		t.Errorf("name = %q", got)
	}
	// A TOML datetime becomes RFC 3339 text so it sorts against every other
	// timestamp the language produces.
	if got := hashStr(t, value, "created"); !strings.HasPrefix(got, "2026-09-06T12:00:00") {
		t.Errorf("created = %q, want RFC 3339", got)
	}
	if !hashBool(t, hashField(t, value, "build"), "strip") {
		t.Error("[build].strip did not survive")
	}
}

func TestTomlStringifyRequiresATableAtTheTop(t *testing.T) {
	errObj := callErr(t, TomlStringify, &object.Array{Elements: []object.Object{str("a")}})
	if !strings.Contains(errObj.Message, "HASH") {
		t.Errorf("error should say a document is a table; got %q", errObj.Message)
	}
}

func TestTomlStringifyRoundTrips(t *testing.T) {
	value := mustCall(t, TomlParse, str("a = 1\nb = \"two\"\n"))
	text := mustCall(t, TomlStringify, value).(*object.String)
	again := mustCall(t, TomlParse, str(text.Value))
	if hashInt(t, again, "a") != 1 || hashStr(t, again, "b") != "two" {
		t.Fatalf("round trip lost data: %q", text.Value)
	}
}

// setHashKey writes one string-keyed entry into a hash, which is what an
// options argument looks like coming from a .mut program.
func setHashKey(t *testing.T, hash *object.Hash, key string, value object.Object) {
	t.Helper()

	if hash.Pairs == nil {
		hash.Pairs = map[object.HashKey]object.HashPair{}
	}
	k := str(key)
	hash.Pairs[k.HashKey()] = object.HashPair{Key: k, Value: value}
}
