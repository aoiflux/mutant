package builtin

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"mutant/object"
)

func DetectPersistence(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	facts, ok := args[0].(*object.Hash)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `detect_persistence` must be HASH, got %s", args[0].Type()))
	}

	suspicious := make([]object.Object, 0)
	for _, field := range []string{"autorun_keys", "startup_files", "scheduled_tasks"} {
		if arr, ok := detectHashArrayByKey(facts, field); ok {
			for _, entry := range arr.Elements {
				strObj, ok := entry.(*object.String)
				if !ok {
					continue
				}
				value := strings.ToLower(strObj.Value)
				if strings.Contains(value, "runonce") || strings.Contains(value, "appdata") || strings.Contains(value, "temp") || strings.Contains(value, "powershell") {
					suspicious = append(suspicious, makeHashObject(map[string]object.Object{
						"category": stringObj(field),
						"entry":    stringObj(strObj.Value),
					}))
				}
			}
		}
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"detected": boolObj(len(suspicious) > 0),
		"count":    intObj(int64(len(suspicious))),
		"hits":     &object.Array{Elements: suspicious},
	}), nil)
}

func DetectInjection(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	facts, ok := args[0].(*object.Hash)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `detect_injection` must be HASH, got %s", args[0].Type()))
	}
	pathObj, ok := detectHashStringByKey(facts, "mem_path")
	if !ok {
		return resultAndError(nil, newError("detect_injection requires facts.mem_path STRING"))
	}

	data, err := os.ReadFile(pathObj)
	if err != nil {
		return resultAndError(nil, newError("detect_injection: %s", err.Error()))
	}

	reasons := make([]object.Object, 0)
	mzOffsets := carveOffsets(data, []byte{0x4d, 0x5a})
	if len(mzOffsets) > 1 {
		reasons = append(reasons, stringObj("multiple_pe_headers"))
	}
	shellHits := 0
	for _, sig := range [][]byte{{0x90, 0x90, 0x90}, {0xfc, 0xe8}, {0x31, 0xc0, 0x50, 0x68}} {
		shellHits += len(carveOffsets(data, sig))
	}
	if shellHits > 0 {
		reasons = append(reasons, stringObj("shellcode_signatures"))
	}

	score := int64(0)
	if len(mzOffsets) > 1 {
		score += 40
	}
	if shellHits > 0 {
		score += 60
	}
	if score > 100 {
		score = 100
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"detected":       boolObj(score >= 60),
		"score":          intObj(score),
		"pe_headers":     intObj(int64(len(mzOffsets))),
		"shellcode_hits": intObj(int64(shellHits)),
		"reasons":        &object.Array{Elements: reasons},
	}), nil)
}

func DetectNetworkBeacon(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	flows, ok := args[0].(*object.Array)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `detect_network_beacon` must be ARRAY, got %s", args[0].Type()))
	}

	byDst := map[string]int64{}
	for idx, flowObj := range flows.Elements {
		flow, ok := flowObj.(*object.Hash)
		if !ok {
			return resultAndError(nil, newError("flow at index %d must be HASH", idx))
		}
		dst, ok := detectHashStringByKey(flow, "dst")
		if !ok {
			return resultAndError(nil, newError("flow at index %d missing STRING dst", idx))
		}
		byDst[strings.ToLower(dst)]++
	}

	hits := make([]object.Object, 0)
	for dst, count := range byDst {
		if count >= 3 {
			hits = append(hits, makeHashObject(map[string]object.Object{
				"dst":   stringObj(dst),
				"count": intObj(count),
			}))
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		hi := hits[i].(*object.Hash)
		hj := hits[j].(*object.Hash)
		di, _ := detectHashStringByKey(hi, "dst")
		dj, _ := detectHashStringByKey(hj, "dst")
		return di < dj
	})

	return resultAndError(makeHashObject(map[string]object.Object{
		"detected": boolObj(len(hits) > 0),
		"hits":     &object.Array{Elements: hits},
	}), nil)
}

func DetectPrivEsc(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	facts, ok := args[0].(*object.Hash)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `detect_priv_esc` must be HASH, got %s", args[0].Type()))
	}

	checks := []string{"token_theft", "uac_bypass", "lsass_access", "se_debug_enabled"}
	hits := make([]object.Object, 0)
	for _, check := range checks {
		if valObj, ok := detectHashValueByKey(facts, check); ok {
			if b, ok := valObj.(*object.Boolean); ok && b.Value {
				hits = append(hits, stringObj(check))
			}
		}
	}

	score := int64(len(hits) * 25)
	if score > 100 {
		score = 100
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"detected": boolObj(len(hits) > 0),
		"score":    intObj(score),
		"signals":  &object.Array{Elements: hits},
	}), nil)
}

func DetectSuspiciousFiles(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	pathsObj, ok := args[0].(*object.Array)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `detect_suspicious_files` must be ARRAY, got %s", args[0].Type()))
	}

	hits := make([]object.Object, 0)
	for idx, pObj := range pathsObj.Elements {
		pathStr, ok := pObj.(*object.String)
		if !ok {
			return resultAndError(nil, newError("path at index %d must be STRING", idx))
		}
		data, err := os.ReadFile(pathStr.Value)
		if err != nil {
			continue
		}
		ent := shannonEntropy(data)
		typ, _, _ := detectMagic(data)
		ext := strings.ToLower(filepath.Ext(pathStr.Value))
		reasons := make([]string, 0)
		if ent > 7.2 {
			reasons = append(reasons, "high_entropy")
		}
		if (typ == "pe" || typ == "elf") && ext == ".txt" {
			reasons = append(reasons, "extension_mismatch")
		}
		if len(reasons) > 0 {
			reasonObjs := make([]object.Object, len(reasons))
			for i, r := range reasons {
				reasonObjs[i] = stringObj(r)
			}
			hits = append(hits, makeHashObject(map[string]object.Object{
				"path":    stringObj(pathStr.Value),
				"entropy": &object.Float{Value: ent},
				"type":    stringObj(typ),
				"reasons": &object.Array{Elements: reasonObjs},
			}))
		}
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"detected": boolObj(len(hits) > 0),
		"count":    intObj(int64(len(hits))),
		"hits":     &object.Array{Elements: hits},
	}), nil)
}

func detectHashValueByKey(hash *object.Hash, key string) (object.Object, bool) {
	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		return nil, false
	}
	return pair.Value, true
}

func detectHashStringByKey(hash *object.Hash, key string) (string, bool) {
	obj, ok := detectHashValueByKey(hash, key)
	if !ok {
		return "", false
	}
	strObj, ok := obj.(*object.String)
	if !ok {
		return "", false
	}
	return strObj.Value, true
}

func detectHashArrayByKey(hash *object.Hash, key string) (*object.Array, bool) {
	obj, ok := detectHashValueByKey(hash, key)
	if !ok {
		return nil, false
	}
	arr, ok := obj.(*object.Array)
	return arr, ok
}
