package builtin

import (
	"debug/dwarf"
	"debug/elf"
	"debug/pe"
	"os"
	"sort"
	"strings"

	"mutant/object"
)

func BinPEParse(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `bin_pe_parse` must be STRING, got %s", args[0].Type()))
	}

	f, err := pe.Open(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("bin_pe_parse: %s", err.Error()))
	}
	defer f.Close()

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":            stringObj(pathObj.Value),
		"format":          stringObj("pe"),
		"machine":         intObj(int64(f.FileHeader.Machine)),
		"num_sections":    intObj(int64(f.FileHeader.NumberOfSections)),
		"characteristics": intObj(int64(f.FileHeader.Characteristics)),
		"timestamp":       intObj(int64(f.FileHeader.TimeDateStamp)),
	}), nil)
}

func BinELFParse(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `bin_elf_parse` must be STRING, got %s", args[0].Type()))
	}

	f, err := elf.Open(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("bin_elf_parse: %s", err.Error()))
	}
	defer f.Close()

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":         stringObj(pathObj.Value),
		"format":       stringObj("elf"),
		"class":        stringObj(f.Class.String()),
		"data":         stringObj(f.Data.String()),
		"machine":      stringObj(f.Machine.String()),
		"type":         stringObj(f.Type.String()),
		"entry":        intObj(int64(f.Entry)),
		"num_sections": intObj(int64(len(f.Sections))),
	}), nil)
}

func BinDWARFParse(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `bin_dwarf_parse` must be STRING, got %s", args[0].Type()))
	}

	format, data, errObj := loadDWARF(pathObj.Value)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	compileUnits := int64(0)
	if data != nil {
		reader := data.Reader()
		for {
			entry, err := reader.Next()
			if err != nil || entry == nil {
				break
			}
			if entry.Tag == dwarf.TagCompileUnit {
				compileUnits++
			}
		}
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":          stringObj(pathObj.Value),
		"format":        stringObj(format),
		"compile_units": intObj(compileUnits),
	}), nil)
}

func BinStrings(args ...object.Object) object.Object {
	if len(args) != 1 && len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `bin_strings` must be STRING, got %s", args[0].Type()))
	}

	minLen := int64(4)
	if len(args) == 2 {
		minLenObj, ok := args[1].(*object.Integer)
		if !ok {
			return resultAndError(nil, newError("argument 2 to `bin_strings` must be INTEGER, got %s", args[1].Type()))
		}
		if minLenObj.Value < 1 {
			return resultAndError(nil, newError("argument 2 to `bin_strings` must be >= 1"))
		}
		minLen = minLenObj.Value
	}

	data, err := os.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("bin_strings: %s", err.Error()))
	}

	values := extractPrintableStrings(data, int(minLen))
	elements := make([]object.Object, len(values))
	for i, v := range values {
		elements[i] = stringObj(v)
	}

	return resultAndError(&object.Array{Elements: elements}, nil)
}

func BinEntropy(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `bin_entropy` must be STRING, got %s", args[0].Type()))
	}

	data, err := os.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("bin_entropy: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":    stringObj(pathObj.Value),
		"bytes":   intObj(int64(len(data))),
		"entropy": &object.Float{Value: shannonEntropy(data)},
	}), nil)
}

func BinYaraScan(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `bin_yara_scan` must be STRING, got %s", args[0].Type()))
	}
	rulesObj, ok := args[1].(*object.Array)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `bin_yara_scan` must be ARRAY, got %s", args[1].Type()))
	}

	data, err := os.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("bin_yara_scan: %s", err.Error()))
	}
	lowerData := strings.ToLower(string(data))

	hits := make([]object.Object, 0)
	for i, ruleObj := range rulesObj.Elements {
		ruleStr, ok := ruleObj.(*object.String)
		if !ok {
			return resultAndError(nil, newError("argument 2 to `bin_yara_scan` must contain STRING rules. element %d got %s", i, ruleObj.Type()))
		}
		pattern := strings.ToLower(ruleStr.Value)
		if pattern == "" {
			continue
		}
		offset := strings.Index(lowerData, pattern)
		if offset >= 0 {
			hits = append(hits, makeHashObject(map[string]object.Object{
				"rule":   stringObj(ruleStr.Value),
				"offset": intObj(int64(offset)),
			}))
		}
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":        stringObj(pathObj.Value),
		"engine":      stringObj("yara-lite"),
		"total_rules": intObj(int64(len(rulesObj.Elements))),
		"matched":     intObj(int64(len(hits))),
		"hits":        &object.Array{Elements: hits},
	}), nil)
}

func BinImports(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `bin_imports` must be STRING, got %s", args[0].Type()))
	}

	format, imports, errObj := loadImports(pathObj.Value)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	sort.Strings(imports)
	imports = uniqueStrings(imports)
	elements := make([]object.Object, len(imports))
	for i, v := range imports {
		elements[i] = stringObj(v)
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":    stringObj(pathObj.Value),
		"format":  stringObj(format),
		"imports": &object.Array{Elements: elements},
	}), nil)
}

func BinSections(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `bin_sections` must be STRING, got %s", args[0].Type()))
	}

	format, sections, errObj := loadSections(pathObj.Value)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":     stringObj(pathObj.Value),
		"format":   stringObj(format),
		"sections": &object.Array{Elements: sections},
	}), nil)
}

func loadDWARF(path string) (string, *dwarf.Data, *object.Error) {
	if peFile, err := pe.Open(path); err == nil {
		defer peFile.Close()
		data, derr := peFile.DWARF()
		if derr != nil {
			return "pe", nil, newError("bin_dwarf_parse: %s", derr.Error())
		}
		return "pe", data, nil
	}
	if elfFile, err := elf.Open(path); err == nil {
		defer elfFile.Close()
		data, derr := elfFile.DWARF()
		if derr != nil {
			return "elf", nil, newError("bin_dwarf_parse: %s", derr.Error())
		}
		return "elf", data, nil
	}
	return "", nil, newError("bin_dwarf_parse: unsupported or invalid binary format")
}

func loadImports(path string) (string, []string, *object.Error) {
	if peFile, err := pe.Open(path); err == nil {
		defer peFile.Close()
		imports, ierr := peFile.ImportedSymbols()
		if ierr != nil {
			return "pe", nil, newError("bin_imports: %s", ierr.Error())
		}
		return "pe", imports, nil
	}
	if elfFile, err := elf.Open(path); err == nil {
		defer elfFile.Close()
		libs, lerr := elfFile.ImportedLibraries()
		if lerr != nil {
			return "elf", nil, newError("bin_imports: %s", lerr.Error())
		}
		syms, serr := elfFile.ImportedSymbols()
		if serr != nil {
			return "elf", nil, newError("bin_imports: %s", serr.Error())
		}
		all := make([]string, 0, len(libs)+len(syms))
		all = append(all, libs...)
		for _, sym := range syms {
			all = append(all, sym.Name)
		}
		return "elf", all, nil
	}
	return "", nil, newError("bin_imports: unsupported or invalid binary format")
}

func loadSections(path string) (string, []object.Object, *object.Error) {
	if peFile, err := pe.Open(path); err == nil {
		defer peFile.Close()
		sections := make([]object.Object, 0, len(peFile.Sections))
		for _, sec := range peFile.Sections {
			sections = append(sections, makeHashObject(map[string]object.Object{
				"name": stringObj(strings.TrimSpace(sec.Name)),
				"size": intObj(int64(sec.Size)),
				"addr": intObj(int64(sec.VirtualAddress)),
			}))
		}
		return "pe", sections, nil
	}
	if elfFile, err := elf.Open(path); err == nil {
		defer elfFile.Close()
		sections := make([]object.Object, 0, len(elfFile.Sections))
		for _, sec := range elfFile.Sections {
			sections = append(sections, makeHashObject(map[string]object.Object{
				"name": stringObj(sec.Name),
				"size": intObj(int64(sec.Size)),
				"addr": intObj(int64(sec.Addr)),
			}))
		}
		return "elf", sections, nil
	}
	return "", nil, newError("bin_sections: unsupported or invalid binary format")
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := make([]string, 0, len(values))
	last := ""
	for i, v := range values {
		if i == 0 || v != last {
			out = append(out, v)
			last = v
		}
	}
	return out
}
