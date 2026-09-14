package builtin

import (
	"strings"
	"testing"

	"mutant/object"
)

// A bundle fails differently from a document. An ECS document that is wrong gets
// indexed under the wrong category and can be found again; a STIX object whose
// id is wrong is simply never matched by anything, and the pipeline that ignores
// it reports nothing at all. The id is the whole contract: it is how two tools
// that saw the same indicator agree they saw the same indicator.
//
// So the ids below are pinned to values computed outside this tree, by the
// algorithm the specification names -- UUIDv5 over the RFC 8785 canonical form
// of the ID contributing properties, under STIX's own namespace. If a change
// here alters how the name is built, these break, which is the point: nothing in
// the output would otherwise look any different.

// bundleOf builds a bundle and returns its objects.
func bundleOf(t *testing.T, iocs map[string]object.Object, opts ...object.Object) []*object.Hash {
	t.Helper()
	args := []object.Object{makeHashObject(iocs)}
	args = append(args, opts...)

	payload, errObj := unwrapPair(t, StixBundle(args...))
	if errObj != nil {
		t.Fatalf("stix_bundle refused a valid input: %s", errObj.Inspect())
	}
	bundle, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("stix_bundle returned %s, want HASH", payload.Type())
	}
	if kind := hStr(t, bundle, "type"); kind != "bundle" {
		t.Fatalf("bundle type = %q, want \"bundle\"", kind)
	}
	if id := hStr(t, bundle, "id"); !strings.HasPrefix(id, "bundle--") {
		t.Fatalf("bundle id = %q, want a bundle-- identifier", id)
	}

	held := docAt(t, bundle, "objects")
	if held == nil {
		return nil
	}
	array, ok := held.(*object.Array)
	if !ok {
		t.Fatalf("bundle objects is %s, want ARRAY", held.Type())
	}
	out := make([]*object.Hash, 0, len(array.Elements))
	for i, element := range array.Elements {
		nested, ok := element.(*object.Hash)
		if !ok {
			t.Fatalf("bundle object %d is %s, want HASH", i, element.Type())
		}
		out = append(out, nested)
	}
	return out
}

func stixList(values ...string) object.Object { return stringArrayObj(values) }

func refuseBundle(t *testing.T, iocs map[string]object.Object, opts ...object.Object) string {
	t.Helper()
	args := []object.Object{makeHashObject(iocs)}
	args = append(args, opts...)

	_, errObj := unwrapPairNoFatal(StixBundle(args...))
	if errObj == nil {
		t.Fatal("stix_bundle accepted what it should have refused")
	}
	return errObj.Message
}

func TestStixObservableIdsAreTheOnesEveryOtherToolDerives(t *testing.T) {
	cases := []struct {
		key   string
		value string
		id    string
	}{
		{"ipv4", "198.51.100.3", "ipv4-addr--28bb3599-77cd-5a82-a950-b5bc3caf07c4"},
		{"ipv6", "2001:db8::1", "ipv6-addr--6469e3a9-b053-5e34-a025-9396ae051d26"},
		{"domains", "example.com", "domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7"},
		// A URL with an ampersand in it. encoding/json escapes that
		// character unless told otherwise, and an id computed over the
		// escaped form is one nothing else in the world arrives at.
		{"urls", "http://example.com/a?x=1&y=2", "url--ae873ad5-e6a3-51e3-9038-5690ac1c832b"},
		{"emails", "a@example.com", "email-addr--8f5f7fba-cc24-5e3f-aca4-f7194112e042"},
		{"md5", "d41d8cd98f00b204e9800998ecf8427e", "file--02fff920-f614-527c-81d1-6353633a6d21"},
		{"sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "file--fa6e66a5-f019-51f9-8ab5-812023e58c6e"},
		{"sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "file--22f8ff52-8f62-5f03-a53a-6f50f54fd74c"},
	}

	for _, testCase := range cases {
		t.Run(testCase.key, func(t *testing.T) {
			objects := bundleOf(t, map[string]object.Object{testCase.key: stixList(testCase.value)})
			if len(objects) != 1 {
				t.Fatalf("got %d objects, want 1", len(objects))
			}
			if id := hStr(t, objects[0], "id"); id != testCase.id {
				t.Errorf("id = %q, want %q", id, testCase.id)
			}
		})
	}
}

// The escaping is checked at the point it happens too, because the id above
// would be just as wrong-looking-right if the canonical form changed and the
// pinned value were updated to match it.
func TestStixCanonicalFormLeavesJsonsOwnEscapingOut(t *testing.T) {
	canonical, errObj := stixCanonicalJSON("url", map[string]any{"value": "http://example.com/a?x=1&y=2"})
	if errObj != nil {
		t.Fatalf("canonicalizing failed: %s", errObj.Inspect())
	}
	want := `{"value":"http://example.com/a?x=1&y=2"}`
	if string(canonical) != want {
		t.Errorf("canonical form = %s, want %s", canonical, want)
	}
}

func TestStixObservablesCarryOnlyWhatIdentifiesThem(t *testing.T) {
	objects := bundleOf(t, map[string]object.Object{
		"domains": stixList("example.com"),
		"md5":     stixList("d41d8cd98f00b204e9800998ecf8427e"),
	})
	if len(objects) != 2 {
		t.Fatalf("got %d objects, want 2", len(objects))
	}

	domain := objects[0]
	if kind := hStr(t, domain, "type"); kind != "domain-name" {
		t.Errorf("type = %q, want \"domain-name\"", kind)
	}
	if value := hStr(t, domain, "value"); value != "example.com" {
		t.Errorf("value = %q", value)
	}
	// A Cyber-observable Object carries no timestamps of its own, and inventing
	// one would date the indicator to when the script ran rather than to
	// anything the evidence says.
	for _, absent := range []string{"created", "modified", "valid_from", "labels"} {
		if docAt(t, domain, absent) != nil {
			t.Errorf("observable carries %q, which a STIX observable has no place for", absent)
		}
	}

	file := objects[1]
	if kind := hStr(t, file, "type"); kind != "file" {
		t.Errorf("type = %q, want \"file\"", kind)
	}
	if digest := docStr(t, file, "hashes.MD5"); digest != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("hashes.MD5 = %q", digest)
	}
	// STIX requires a file's name when it has one; this one has none, and a
	// name invented from the digest would be a claim about the file.
	if docAt(t, file, "name") != nil {
		t.Error("file observable carries a name nothing recorded")
	}
}

func TestStixThreeDigestsOfOneFileAreThreeObservables(t *testing.T) {
	objects := bundleOf(t, map[string]object.Object{
		"md5":    stixList("d41d8cd98f00b204e9800998ecf8427e"),
		"sha1":   stixList("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
		"sha256": stixList("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
	})
	if len(objects) != 3 {
		t.Fatalf("got %d objects, want 3 -- nothing in a list of digests says they describe one file", len(objects))
	}
	for i, algorithm := range []string{"MD5", "SHA-1", "SHA-256"} {
		if docAt(t, objects[i], "hashes."+algorithm) == nil {
			t.Errorf("object %d has no %s", i, algorithm)
		}
		if held := docAt(t, objects[i], "hashes"); held != nil {
			if hash, ok := held.(*object.Hash); ok && len(hash.Pairs) != 1 {
				t.Errorf("object %d carries %d hashes, want the one it was given", i, len(hash.Pairs))
			}
		}
	}
}

func TestStixNormalizesSoOneIndicatorIsOneObject(t *testing.T) {
	objects := bundleOf(t, map[string]object.Object{
		// The same digest twice, the same domain twice, the same address
		// twice -- each written the way it turns up in a report, and each
		// written the ordinary way.
		"md5":     stixList("D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e"),
		"domains": stixList("Example.COM", "example.com"),
		"ipv6":    stixList("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
	})
	if len(objects) != 3 {
		t.Fatalf("got %d objects, want 3: a spelling is not a second indicator", len(objects))
	}
	if id := hStr(t, objects[1], "id"); id != "domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7" {
		t.Errorf("the capitalized domain did not normalize: %s", id)
	}
}

func TestStixBundleTakesExtractIocsOutputDirectly(t *testing.T) {
	report := "Beacon to hxxp://evil[.]example[.]com/gate.php from 203[.]0[.]113[.]7, " +
		"dropper d41d8cd98f00b204e9800998ecf8427e, contact mallory@evil.example.com."

	payload, errObj := unwrapPair(t, StixBundle(ExtractIOCs(stringObj(report))))
	if errObj != nil {
		t.Fatalf("stix_bundle refused extract_iocs output: %s", errObj.Inspect())
	}
	bundle, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("stix_bundle returned %s, want HASH", payload.Type())
	}

	held := docAt(t, bundle, "objects")
	if held == nil {
		t.Fatal("the bundle has no objects; the extraction found several")
	}
	types := map[string]int{}
	for _, element := range held.(*object.Array).Elements {
		types[hStr(t, element.(*object.Hash), "type")]++
	}
	for _, wanted := range []string{"ipv4-addr", "domain-name", "url", "email-addr", "file"} {
		if types[wanted] == 0 {
			t.Errorf("no %s observable; extract_iocs found one", wanted)
		}
	}
}

func TestStixBundleIsTheSameBundleTwice(t *testing.T) {
	iocs := map[string]object.Object{
		"ipv4":    stixList("198.51.100.3", "203.0.113.7"),
		"domains": stixList("evil.example.com"),
		"sha256":  stixList("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
	}
	opts := makeHashObject(map[string]object.Object{
		"indicators": boolObj(true),
		"created":    stringObj("2026-01-31T09:00:00Z"),
	})

	render := func() string {
		payload, errObj := unwrapPair(t, StixBundle(makeHashObject(iocs), opts))
		if errObj != nil {
			t.Fatalf("stix_bundle refused a valid input: %s", errObj.Inspect())
		}
		text, errObj := unwrapPair(t, JsonStringify(payload))
		if errObj != nil {
			t.Fatalf("the bundle would not serialize: %s", errObj.Inspect())
		}
		return text.(*object.String).Value
	}

	first, second := render(), render()
	if first != second {
		t.Error("two runs over one set of indicators produced two different bundles")
	}
	if !strings.Contains(first, `"bundle--`) {
		t.Errorf("bundle id missing from %s", first)
	}
}

func TestStixIndicatorsAreOptionalAndConcludeNothing(t *testing.T) {
	iocs := map[string]object.Object{"domains": stixList("evil.example.com")}

	if objects := bundleOf(t, iocs); len(objects) != 1 {
		t.Fatalf("got %d objects with indicators off, want the observable alone", len(objects))
	}

	objects := bundleOf(t, iocs, makeHashObject(map[string]object.Object{
		"indicators": boolObj(true),
		"created":    stringObj("2026-01-31T09:00:00Z"),
		"tags":       stixList("case-42"),
	}))
	if len(objects) != 2 {
		t.Fatalf("got %d objects, want the observable and its indicator", len(objects))
	}

	indicator := objects[1]
	if kind := hStr(t, indicator, "type"); kind != "indicator" {
		t.Fatalf("second object is %q, want an indicator", kind)
	}
	if version := hStr(t, indicator, "spec_version"); version != "2.1" {
		t.Errorf("spec_version = %q", version)
	}
	if pattern := hStr(t, indicator, "pattern"); pattern != "[domain-name:value = 'evil.example.com']" {
		t.Errorf("pattern = %q", pattern)
	}
	if kind := hStr(t, indicator, "pattern_type"); kind != "stix" {
		t.Errorf("pattern_type = %q, want \"stix\"", kind)
	}
	// The three timestamps an Indicator requires all come from the option, so a
	// pinned case time is the only clock that reaches the bundle.
	for _, field := range []string{"created", "modified", "valid_from"} {
		if stamp := hStr(t, indicator, field); stamp != "2026-01-31T09:00:00.000Z" {
			t.Errorf("%s = %q", field, stamp)
		}
	}
	if types := docList(t, indicator, "indicator_types"); len(types) != 1 || types[0] != "unknown" {
		t.Errorf("indicator_types = %v; extraction found the value, it concluded nothing about it", types)
	}
	if labels := docList(t, indicator, "labels"); len(labels) != 1 || labels[0] != "case-42" {
		t.Errorf("labels = %v", labels)
	}
}

// The indicator's id is derived from its pattern alone, so re-stamping a case
// does not renumber everything in it.
func TestStixIndicatorKeepsItsIdWhenTheCaseIsRestamped(t *testing.T) {
	iocs := map[string]object.Object{"domains": stixList("evil.example.com")}
	ids := make([]string, 0, 2)
	for _, stamp := range []string{"2026-01-31T09:00:00Z", "2026-02-01T17:45:00Z"} {
		objects := bundleOf(t, iocs, makeHashObject(map[string]object.Object{
			"indicators": boolObj(true),
			"created":    stringObj(stamp),
		}))
		ids = append(ids, hStr(t, objects[1], "id"))
	}
	if ids[0] != ids[1] {
		t.Errorf("the same indicator got two ids: %s and %s", ids[0], ids[1])
	}
}

func TestStixBundleWithNothingFoundHasNoObjectsKey(t *testing.T) {
	objects := bundleOf(t, map[string]object.Object{"domains": stringArrayObj(nil)})
	if len(objects) != 0 {
		t.Fatalf("got %d objects from an empty extraction", len(objects))
	}
}

func TestStixBundleRefusesAValueThatIsNotWhatItsKeySays(t *testing.T) {
	cases := []struct {
		name    string
		iocs    map[string]object.Object
		mention string
	}{
		{"a sha1 digest filed as a sha256",
			map[string]object.Object{"sha256": stixList("da39a3ee5e6b4b0d3255bfef95601890afd80709")},
			"SHA-256 digest"},
		{"a digest with a non-hex character",
			map[string]object.Object{"md5": stixList("z41d8cd98f00b204e9800998ecf8427e")},
			"hexadecimal"},
		{"a hostname filed as a url",
			map[string]object.Object{"urls": stixList("evil.example.com")},
			"is not a URL"},
		{"something that is not an address",
			map[string]object.Object{"ipv4": stixList("not-an-address")},
			"IPv4"},
		{"an address of the other family",
			map[string]object.Object{"ipv4": stixList("2001:db8::1")},
			"IPv4"},
		{"an empty value",
			map[string]object.Object{"domains": stixList("   ")},
			"empty"},
		{"a key no indicator type claims",
			map[string]object.Object{"hash": stixList("d41d8cd98f00b204e9800998ecf8427e")},
			"unknown indicator type"},
		{"a value that is not text",
			map[string]object.Object{"ipv4": &object.Array{Elements: []object.Object{intObj(7)}}},
			"must be a STRING"},
		{"a whole list that is not a list",
			map[string]object.Object{"ipv4": intObj(7)},
			"STRING or an ARRAY"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			message := refuseBundle(t, testCase.iocs)
			if !strings.Contains(message, testCase.mention) {
				t.Errorf("error %q does not mention %q", message, testCase.mention)
			}
		})
	}
}

func TestStixOptionsAreCheckedBeforeAnythingIsBuilt(t *testing.T) {
	iocs := map[string]object.Object{"domains": stixList("example.com")}

	t.Run("an option nobody accepts", func(t *testing.T) {
		message := refuseBundle(t, iocs, makeHashObject(map[string]object.Object{"indicator": boolObj(true)}))
		if !strings.Contains(message, "unknown option") {
			t.Errorf("error = %q", message)
		}
	})

	t.Run("a created that is not a timestamp", func(t *testing.T) {
		message := refuseBundle(t, iocs, makeHashObject(map[string]object.Object{"created": stringObj("last tuesday")}))
		if !strings.Contains(message, "RFC 3339") {
			t.Errorf("error = %q", message)
		}
	})

	// A STIX observable has no labels property, so tags with no indicators to
	// carry them would vanish into a bundle that still looked complete.
	t.Run("tags with nothing to attach to", func(t *testing.T) {
		message := refuseBundle(t, iocs, makeHashObject(map[string]object.Object{"tags": stixList("case-42")}))
		if !strings.Contains(message, "indicators: true") {
			t.Errorf("error = %q", message)
		}
	})
}

func TestStixBundleTakesOneIndicatorWrittenAsItself(t *testing.T) {
	objects := bundleOf(t, map[string]object.Object{"domain": stringObj("example.com")})
	if len(objects) != 1 {
		t.Fatalf("got %d objects, want 1", len(objects))
	}
	if id := hStr(t, objects[0], "id"); id != "domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7" {
		t.Errorf("id = %q", id)
	}
}

func TestStixPatternNamesThePathEachTypeIsMatchedOn(t *testing.T) {
	cases := []struct {
		kind    string
		value   string
		pattern string
	}{
		{"ipv4", "198.51.100.3", "[ipv4-addr:value = '198.51.100.3']"},
		{"ipv6", "2001:db8::1", "[ipv6-addr:value = '2001:db8::1']"},
		{"domains", "evil.example.com", "[domain-name:value = 'evil.example.com']"},
		{"domain", "evil.example.com", "[domain-name:value = 'evil.example.com']"},
		{"urls", "http://evil.example.com/gate.php", "[url:value = 'http://evil.example.com/gate.php']"},
		{"emails", "Mallory@Evil.Example.com", "[email-addr:value = 'mallory@evil.example.com']"},
		{"md5", "D41D8CD98F00B204E9800998ECF8427E", "[file:hashes.'MD5' = 'd41d8cd98f00b204e9800998ecf8427e']"},
		{"sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']"},
		{"sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']"},
	}

	for _, testCase := range cases {
		t.Run(testCase.kind+"/"+testCase.value, func(t *testing.T) {
			payload, errObj := unwrapPair(t, StixPattern(stringObj(testCase.kind), stringObj(testCase.value)))
			if errObj != nil {
				t.Fatalf("stix_pattern refused a valid indicator: %s", errObj.Inspect())
			}
			if pattern := payload.(*object.String).Value; pattern != testCase.pattern {
				t.Errorf("pattern = %s, want %s", pattern, testCase.pattern)
			}
		})
	}
}

// A quote in a URL would otherwise close the pattern's own string and leave the
// rest of the value sitting in the grammar as if someone had written it there.
func TestStixPatternEscapesTheValueItQuotes(t *testing.T) {
	payload, errObj := unwrapPair(t, StixPattern(stringObj("url"), stringObj(`http://evil.example.com/a'b\c`)))
	if errObj != nil {
		t.Fatalf("stix_pattern refused a valid URL: %s", errObj.Inspect())
	}
	want := `[url:value = 'http://evil.example.com/a\'b\\c']`
	if pattern := payload.(*object.String).Value; pattern != want {
		t.Errorf("pattern = %s, want %s", pattern, want)
	}
}

func TestStixPatternRefusesWhatItCannotMatchOn(t *testing.T) {
	cases := []struct {
		name    string
		args    []object.Object
		mention string
	}{
		{"a type nobody knows", []object.Object{stringObj("registry_key"), stringObj("HKLM\\Run")}, "unknown indicator type"},
		{"a value that is not one", []object.Object{stringObj("ipv4"), stringObj("evil.example.com")}, "IPv4"},
		{"one argument", []object.Object{stringObj("ipv4")}, "wrong number of arguments"},
		{"a type that is not text", []object.Object{intObj(4), stringObj("198.51.100.3")}, "STRING"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, errObj := unwrapPairNoFatal(StixPattern(testCase.args...))
			if errObj == nil {
				t.Fatal("stix_pattern accepted what it should have refused")
			}
			if !strings.Contains(errObj.Message, testCase.mention) {
				t.Errorf("error %q does not mention %q", errObj.Message, testCase.mention)
			}
		})
	}
}

// The bundle's pattern and its indicator's pattern have to be the one string, or
// an analyst reading the bundle and a script building a query disagree about
// what is being hunted.
func TestStixPatternAndBundleAgree(t *testing.T) {
	value := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	objects := bundleOf(t, map[string]object.Object{"sha256": stixList(value)},
		makeHashObject(map[string]object.Object{"indicators": boolObj(true)}))
	if len(objects) != 2 {
		t.Fatalf("got %d objects, want the observable and its indicator", len(objects))
	}

	payload, errObj := unwrapPair(t, StixPattern(stringObj("sha256"), stringObj(value)))
	if errObj != nil {
		t.Fatalf("stix_pattern refused: %s", errObj.Inspect())
	}
	if standalone, embedded := payload.(*object.String).Value, hStr(t, objects[1], "pattern"); standalone != embedded {
		t.Errorf("stix_pattern gives %s, the bundle carries %s", standalone, embedded)
	}
}

func TestStixBundleRefusesWhatIsNotAnIndicatorHash(t *testing.T) {
	cases := []struct {
		name    string
		args    []object.Object
		mention string
	}{
		{"no arguments", nil, "wrong number of arguments"},
		{"an array of indicators", []object.Object{stixList("198.51.100.3")}, "must be a HASH"},
		{"a parser's failure, carried out", []object.Object{&object.MultiValue{Values: []object.Object{
			&object.Null{}, &object.Error{Message: "json_parse: unexpected end of input"},
		}}}, "json_parse"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, errObj := unwrapPairNoFatal(StixBundle(testCase.args...))
			if errObj == nil {
				t.Fatal("stix_bundle accepted what it should have refused")
			}
			if !strings.Contains(errObj.Message, testCase.mention) {
				t.Errorf("error %q does not mention %q", errObj.Message, testCase.mention)
			}
		})
	}
}
