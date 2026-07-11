package builtin

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"

	"mutant/object"
)

type regoPolicyProgram struct {
	Name       string
	Package    string
	Module     string
	EvalQuery  string
	AllowQuery string
	RulesQuery string
}

var policyStore = struct {
	sync.RWMutex
	defs map[string]regoPolicyProgram
}{
	defs: map[string]regoPolicyProgram{},
}

func PolicyLoad(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	nameObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `policy_load` must be STRING, got %s", args[0].Type()))
	}
	if strings.TrimSpace(nameObj.Value) == "" {
		return resultAndError(nil, newError("argument 1 to `policy_load` must not be empty"))
	}

	program, errObj := parseRegoProgram(nameObj.Value, args[1])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	if errObj := validateRegoProgram(program); errObj != nil {
		return resultAndError(nil, errObj)
	}

	policyStore.Lock()
	policyStore.defs[program.Name] = program
	policyStore.Unlock()

	return resultAndError(makeHashObject(map[string]object.Object{
		"name":        stringObj(program.Name),
		"package":     stringObj(program.Package),
		"loaded":      boolObj(true),
		"eval_query":  stringObj(program.EvalQuery),
		"allow_query": stringObj(program.AllowQuery),
		"rules_query": stringObj(program.RulesQuery),
	}), nil)
}

func PolicyRules(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	program, errObj := resolvePolicyProgram(args[0], "policy_rules")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	rulesObj, errObj := evalRegoQuery(program, program.RulesQuery, nil, false)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	return resultAndError(rulesObj, nil)
}

func PolicyEval(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	program, errObj := resolvePolicyProgram(args[0], "policy_eval")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	input, errObj := objectToGoInput(args[1], "policy_eval")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	evaluated, errObj := evalRegoQuery(program, program.EvalQuery, input, false)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	allowObj, errObj := evalRegoQuery(program, program.AllowQuery, input, false)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	allowBool, ok := allowObj.(*object.Boolean)
	if !ok {
		return resultAndError(nil, newError("policy_eval expected boolean result from allow query `%s`", program.AllowQuery))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"allow":    allowBool,
		"query":    stringObj(program.EvalQuery),
		"decision": evaluated,
	}), nil)
}

func PolicyAllow(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	program, errObj := resolvePolicyProgram(args[0], "policy_allow")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	input, errObj := objectToGoInput(args[1], "policy_allow")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	allowObj, errObj := evalRegoQuery(program, program.AllowQuery, input, false)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	allowBool, ok := allowObj.(*object.Boolean)
	if !ok {
		return resultAndError(nil, newError("policy_allow expected boolean result from query `%s`", program.AllowQuery))
	}

	return resultAndError(allowBool, nil)
}

func PolicyTrace(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	program, errObj := resolvePolicyProgram(args[0], "policy_trace")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	input, errObj := objectToGoInput(args[1], "policy_trace")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	traceObj, errObj := evalRegoQuery(program, program.EvalQuery, input, true)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	return resultAndError(traceObj, nil)
}

func parseRegoProgram(name string, source object.Object) (regoPolicyProgram, *object.Error) {
	program := regoPolicyProgram{Name: name}

	switch src := source.(type) {
	case *object.String:
		program.Module = src.Value
	case *object.Hash:
		moduleObj, ok := policyHashGetByStringKey(src, "module")
		if !ok {
			return regoPolicyProgram{}, newError("policy_load source HASH must include `module`")
		}
		moduleStr, ok := moduleObj.(*object.String)
		if !ok {
			return regoPolicyProgram{}, newError("policy_load source key `module` must be STRING")
		}
		program.Module = moduleStr.Value

		if queryObj, ok := policyHashGetByStringKey(src, "eval_query"); ok {
			queryStr, ok := queryObj.(*object.String)
			if !ok {
				return regoPolicyProgram{}, newError("policy_load source key `eval_query` must be STRING")
			}
			program.EvalQuery = queryStr.Value
		}
		if queryObj, ok := policyHashGetByStringKey(src, "allow_query"); ok {
			queryStr, ok := queryObj.(*object.String)
			if !ok {
				return regoPolicyProgram{}, newError("policy_load source key `allow_query` must be STRING")
			}
			program.AllowQuery = queryStr.Value
		}
		if queryObj, ok := policyHashGetByStringKey(src, "rules_query"); ok {
			queryStr, ok := queryObj.(*object.String)
			if !ok {
				return regoPolicyProgram{}, newError("policy_load source key `rules_query` must be STRING")
			}
			program.RulesQuery = queryStr.Value
		}
	default:
		return regoPolicyProgram{}, newError("argument 2 to `policy_load` must be STRING or HASH, got %s", source.Type())
	}

	program.Package = parseRegoPackage(program.Module)
	if program.Package == "" {
		return regoPolicyProgram{}, newError("policy_load: could not parse package name from Rego module")
	}

	if strings.TrimSpace(program.EvalQuery) == "" {
		program.EvalQuery = "data." + program.Package + ".decision"
	}
	if strings.TrimSpace(program.AllowQuery) == "" {
		program.AllowQuery = "data." + program.Package + ".allow"
	}
	if strings.TrimSpace(program.RulesQuery) == "" {
		program.RulesQuery = "data." + program.Package + ".rules"
	}

	return program, nil
}

func validateRegoProgram(program regoPolicyProgram) *object.Error {
	ctx := context.Background()
	queries := []string{program.EvalQuery, program.AllowQuery, program.RulesQuery}
	for _, q := range queries {
		r := rego.New(
			rego.Query(q),
			rego.Module(program.Name+".rego", program.Module),
		)
		if _, err := r.Eval(ctx); err != nil {
			return newError("policy_load: rego validation failed for query `%s`: %s", q, err.Error())
		}
	}
	return nil
}

func resolvePolicyProgram(policyObj object.Object, opName string) (regoPolicyProgram, *object.Error) {
	switch p := policyObj.(type) {
	case *object.String:
		policyStore.RLock()
		defer policyStore.RUnlock()
		program, ok := policyStore.defs[p.Value]
		if !ok {
			return regoPolicyProgram{}, newError("policy `%s` not found", p.Value)
		}
		return program, nil
	case *object.Hash:
		return parseRegoProgram("inline", p)
	default:
		return regoPolicyProgram{}, newError("argument 1 to `%s` must be STRING or HASH, got %s", opName, policyObj.Type())
	}
}

func objectToGoInput(inputObj object.Object, opName string) (any, *object.Error) {
	_, ok := inputObj.(*object.Hash)
	if !ok {
		return nil, newError("argument 2 to `%s` must be HASH, got %s", opName, inputObj.Type())
	}

	value, err := objectToJSONValue(inputObj)
	if err != nil {
		return nil, newError("argument 2 to `%s` could not be converted to JSON value: %s", opName, err.Error())
	}
	return value, nil
}

func evalRegoQuery(program regoPolicyProgram, query string, input any, withTrace bool) (object.Object, *object.Error) {
	ctx := context.Background()
	options := []func(*rego.Rego){
		rego.Query(query),
		rego.Module(program.Name+".rego", program.Module),
	}
	if input != nil {
		options = append(options, rego.Input(input))
	}

	var tracer topdown.BufferTracer
	if withTrace {
		options = append(options, rego.QueryTracer(&tracer))
	}

	r := rego.New(options...)
	results, err := r.Eval(ctx)
	if err != nil {
		return nil, newError("rego evaluation failed for query `%s`: %s", query, err.Error())
	}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		if withTrace {
			return regoTraceToObject(&tracer), nil
		}
		return &object.Null{}, nil
	}

	if withTrace {
		return regoTraceToObject(&tracer), nil
	}

	value := results[0].Expressions[0].Value
	obj, err := jsonValueToObject(value)
	if err != nil {
		jsonBytes, mErr := json.Marshal(value)
		if mErr != nil {
			return nil, newError("rego result conversion failed: %s", err.Error())
		}
		obj = stringObj(string(jsonBytes))
	}
	return obj, nil
}

func regoTraceToObject(tracer *topdown.BufferTracer) object.Object {
	elements := make([]object.Object, len(*tracer))
	for i, event := range *tracer {
		elements[i] = makeHashObject(map[string]object.Object{
			"op":   stringObj(string(event.Op)),
			"node": stringObj(event.Node.String()),
		})
	}
	return &object.Array{Elements: elements}
}

func parseRegoPackage(module string) string {
	re := regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z0-9_\.]+)\s*$`)
	matches := re.FindStringSubmatch(module)
	if len(matches) < 2 {
		return ""
	}
	return strings.TrimSpace(matches[1])
}

func policyHashGetByStringKey(hash *object.Hash, key string) (object.Object, bool) {
	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		return nil, false
	}
	return pair.Value, true
}
