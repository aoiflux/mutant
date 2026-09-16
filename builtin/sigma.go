package builtin

import (
	"bytes"
	"io"
	"sort"

	yaml "go.yaml.in/yaml/v3"

	"mutant/object"
)

// The Sigma builtins. The engine is in sigma_engine.go; this file is the seam
// between it and the language.
//
// A parsed rule is an ordinary hash, not an opaque handle, because everything
// else in Mutant is: it can be printed, stored in a case, diffed against last
// week's copy of the same rule, and handed back to sigma_match. That costs one
// recompile per sigma_match call, which is why sigma_scan exists -- it compiles
// each rule once and then walks the events, and it is the call that runs over a
// timeline.

// SigmaParse compiles one Sigma rule from YAML.
func SigmaParse(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	data, errObj := requireBinaryArg("sigma_parse", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	documents, err := sigmaDecodeYAML(data)
	if err != nil {
		return resultAndError(nil, newError("sigma_parse: %s", err.Error()))
	}
	if len(documents) == 0 {
		return resultAndError(nil, newError("sigma_parse: no rule in the input"))
	}
	if len(documents) > 1 {
		return resultAndError(nil, newError("sigma_parse: the input holds %d YAML documents; a ruleset is sigma_parse_all's job", len(documents)))
	}
	rule, err := compileSigmaRule(documents[0])
	if err != nil {
		return resultAndError(nil, newError("sigma_parse: %s", err.Error()))
	}
	return resultAndError(sigmaRuleHash(rule, documents[0]), nil)
}

// SigmaParseAll compiles every rule in a multi-document YAML file. One bad rule
// fails the call rather than being dropped: a ruleset that silently loads 43 of
// its 44 rules is a ruleset you believe covers something it does not.
func SigmaParseAll(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	data, errObj := requireBinaryArg("sigma_parse_all", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	documents, err := sigmaDecodeYAML(data)
	if err != nil {
		return resultAndError(nil, newError("sigma_parse_all: %s", err.Error()))
	}
	rules := make([]object.Object, 0, len(documents))
	for index, document := range documents {
		if document == nil {
			continue // a `---` with nothing after it
		}
		rule, err := compileSigmaRule(document)
		if err != nil {
			return resultAndError(nil, newError("sigma_parse_all: document %d: %s", index, err.Error()))
		}
		rules = append(rules, sigmaRuleHash(rule, document))
	}
	return resultAndError(&object.Array{Elements: rules}, nil)
}

// SigmaMatch asks one rule about one event.
func SigmaMatch(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	rule, errObj := sigmaRuleArg("sigma_match", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	event, ok := args[1].(*object.Hash)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `sigma_match` must be HASH, got %s", args[1].Type()))
	}
	matched, hits, seen, missing := matchSigmaRule(rule, event)
	return resultAndError(sigmaMatchHash(rule, matched, hits, seen, missing), nil)
}

// SigmaScan runs a ruleset over a timeline.
func SigmaScan(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	rules, errObj := sigmaRulesArg("sigma_scan", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	events, errObj := sigmaEventsArg("sigma_scan", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	hits := make([]object.Object, 0)
	byLevel := map[string]int64{}
	perRule := make([]object.Object, 0, len(rules))
	neverSeen := map[string]bool{}
	everSeen := map[string]bool{}

	for _, rule := range rules {
		ruleHits := int64(0)
		for index, event := range events {
			matched, searches, seen, missing := matchSigmaRule(rule, event)
			for _, field := range seen {
				everSeen[field] = true
			}
			for _, field := range missing {
				neverSeen[field] = true
			}
			if !matched {
				continue
			}
			ruleHits++
			level := rule.level
			if level == "" {
				level = "unspecified"
			}
			byLevel[level]++
			hits = append(hits, makeHashObject(map[string]object.Object{
				"title":       stringObj(rule.title),
				"id":          stringObj(rule.id),
				"level":       stringObj(level),
				"event_index": intObj(int64(index)),
				"searches":    stringArrayObj(searches),
				"tags":        stringArrayObj(rule.tags),
				"event":       event,
			}))
		}
		perRule = append(perRule, makeHashObject(map[string]object.Object{
			"title": stringObj(rule.title),
			"id":    stringObj(rule.id),
			"level": stringObj(rule.level),
			"hits":  intObj(ruleHits),
		}))
	}

	// A field no event in the whole scan carried is the honest answer to "did
	// this ruleset actually have anything to look at": a rule reading Image
	// against a timeline with no Image field did not clear the host, it never
	// ran.
	unmatched := make([]string, 0, len(neverSeen))
	for field := range neverSeen {
		if !everSeen[field] {
			unmatched = append(unmatched, field)
		}
	}
	sort.Strings(unmatched)

	levels := makeHashObject(map[string]object.Object{})
	for level, count := range byLevel {
		key := &object.String{Value: level}
		levels.Pairs[key.HashKey()] = object.HashPair{Key: key, Value: intObj(count)}
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"rules":            intObj(int64(len(rules))),
		"events":           intObj(int64(len(events))),
		"matched":          intObj(int64(len(hits))),
		"hits":             &object.Array{Elements: hits},
		"by_level":         levels,
		"by_rule":          &object.Array{Elements: perRule},
		"unmatched_fields": stringArrayObj(unmatched),
	}), nil)
}

// --- argument plumbing -----------------------------------------------------

func sigmaDecodeYAML(data []byte) ([]any, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(stripBOM(data)))
	documents := make([]any, 0, 4)
	for index := 0; ; index++ {
		var raw any
		err := decoder.Decode(&raw)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		documents = append(documents, sigmaNormalizeKeys(raw))
	}
	return documents, nil
}

// sigmaNormalizeKeys turns yaml.v3's map[string]any-with-any-keys into the
// map[string]any the compiler expects. A rule whose key is the YAML integer 1
// (`EventID: {1: x}` is not legal Sigma, but `1` as a search identifier reads
// as an integer) still arrives as a string.
func sigmaNormalizeKeys(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, entry := range typed {
			out[key] = sigmaNormalizeKeys(entry)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(typed))
		for key, entry := range typed {
			out[sigmaScalarString(key)] = sigmaNormalizeKeys(entry)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, entry := range typed {
			out = append(out, sigmaNormalizeKeys(entry))
		}
		return out
	}
	return value
}

// sigmaRuleArg accepts a rule as YAML text or as the hash sigma_parse returned.
func sigmaRuleArg(op string, arg object.Object, pos int) (*sigmaRule, *object.Error) {
	switch typed := arg.(type) {
	case *object.String, *object.Bytes:
		data, errObj := requireBinaryArg(op, typed, pos)
		if errObj != nil {
			return nil, errObj
		}
		documents, err := sigmaDecodeYAML(data)
		if err != nil {
			return nil, newError("%s: %s", op, err.Error())
		}
		if len(documents) != 1 {
			return nil, newError("%s: argument %d holds %d YAML documents, want one rule", op, pos, len(documents))
		}
		rule, err := compileSigmaRule(documents[0])
		if err != nil {
			return nil, newError("%s: %s", op, err.Error())
		}
		return rule, nil
	case *object.Hash:
		native, err := objectToNative(typed, false)
		if err != nil {
			return nil, newError("%s: argument %d: %s", op, pos, err.Error())
		}
		rule, err := compileSigmaRule(native)
		if err != nil {
			return nil, newError("%s: %s", op, err.Error())
		}
		return rule, nil
	}
	return nil, newError("argument %d to `%s` must be STRING or HASH, got %s", pos, op, arg.Type())
}

func sigmaRulesArg(op string, arg object.Object, pos int) ([]*sigmaRule, *object.Error) {
	switch typed := arg.(type) {
	case *object.String, *object.Bytes:
		data, errObj := requireBinaryArg(op, typed, pos)
		if errObj != nil {
			return nil, errObj
		}
		documents, err := sigmaDecodeYAML(data)
		if err != nil {
			return nil, newError("%s: %s", op, err.Error())
		}
		rules := make([]*sigmaRule, 0, len(documents))
		for index, document := range documents {
			if document == nil {
				continue
			}
			rule, err := compileSigmaRule(document)
			if err != nil {
				return nil, newError("%s: rule %d: %s", op, index, err.Error())
			}
			rules = append(rules, rule)
		}
		return rules, nil
	case *object.Hash:
		rule, errObj := sigmaRuleArg(op, typed, pos)
		if errObj != nil {
			return nil, errObj
		}
		return []*sigmaRule{rule}, nil
	case *object.Array:
		rules := make([]*sigmaRule, 0, len(typed.Elements))
		for index, element := range typed.Elements {
			rule, errObj := sigmaRuleArg(op, element, pos)
			if errObj != nil {
				return nil, newError("%s: rule %d: %s", op, index, errObj.Message)
			}
			rules = append(rules, rule)
		}
		return rules, nil
	}
	return nil, newError("argument %d to `%s` must be STRING, HASH or ARRAY, got %s", pos, op, arg.Type())
}

func sigmaEventsArg(op string, arg object.Object, pos int) ([]object.Object, *object.Error) {
	switch typed := arg.(type) {
	case *object.Hash:
		return []object.Object{typed}, nil
	case *object.Array:
		events := make([]object.Object, 0, len(typed.Elements))
		for index, element := range typed.Elements {
			if _, ok := element.(*object.Hash); !ok {
				return nil, newError("argument %d to `%s` must hold HASH events. element %d got %s", pos, op, index, element.Type())
			}
			events = append(events, element)
		}
		return events, nil
	}
	return nil, newError("argument %d to `%s` must be HASH or ARRAY, got %s", pos, op, arg.Type())
}

// --- result shapes ---------------------------------------------------------

// sigmaRuleHash renders a compiled rule. The detection block is carried
// verbatim so the hash is a rule, not a description of one: sigma_match takes
// it straight back.
func sigmaRuleHash(rule *sigmaRule, document any) *object.Hash {
	logsource := makeHashObject(map[string]object.Object{})
	for key, value := range rule.logsource {
		keyObj := &object.String{Value: key}
		logsource.Pairs[keyObj.HashKey()] = object.HashPair{Key: keyObj, Value: stringObj(value)}
	}

	detection := object.Object(&object.Hash{Pairs: map[object.HashKey]object.HashPair{}})
	if root, ok := document.(map[string]any); ok {
		if converted, err := nativeToObject(root["detection"]); err == nil {
			detection = converted
		}
	}

	return makeHashObject(map[string]object.Object{
		"title":          stringObj(rule.title),
		"id":             stringObj(rule.id),
		"status":         stringObj(rule.status),
		"description":    stringObj(rule.description),
		"author":         stringObj(rule.author),
		"level":          stringObj(rule.level),
		"logsource":      logsource,
		"tags":           stringArrayObj(rule.tags),
		"references":     stringArrayObj(rule.references),
		"falsepositives": stringArrayObj(rule.falsepositives),
		"condition":      stringObj(rule.condition),
		"searches":       stringArrayObj(rule.names),
		"fields":         stringArrayObj(rule.fields),
		"detection":      detection,
	})
}

func sigmaMatchHash(rule *sigmaRule, matched bool, hits, seen, missing []string) *object.Hash {
	return makeHashObject(map[string]object.Object{
		"matched":        boolObj(matched),
		"title":          stringObj(rule.title),
		"id":             stringObj(rule.id),
		"level":          stringObj(rule.level),
		"condition":      stringObj(rule.condition),
		"tags":           stringArrayObj(rule.tags),
		"searches":       stringArrayObj(hits),
		"fields_read":    stringArrayObj(seen),
		"fields_missing": stringArrayObj(missing),
	})
}
