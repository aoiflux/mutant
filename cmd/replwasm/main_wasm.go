//go:build js && wasm

package main

import (
	"mutant/webrepl"
	"syscall/js"
)

func jsObject(fields map[string]any) js.Value {
	obj := js.Global().Get("Object").New()
	for key, value := range fields {
		obj.Set(key, jsValue(value))
	}
	return obj
}

func jsArray(values []string) js.Value {
	arr := js.Global().Get("Array").New(len(values))
	for index, value := range values {
		arr.SetIndex(index, value)
	}
	return arr
}

func jsValue(value any) any {
	switch typed := value.(type) {
	case []string:
		return jsArray(typed)
	default:
		return typed
	}
}

func main() {
	repl := webrepl.New()

	js.Global().Set("mutantReplEval", js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return jsObject(map[string]any{
				"ok":    false,
				"error": "mutantReplEval expects one argument",
			})
		}

		input := args[0].String()
		output, err := repl.Eval(input)
		if err != nil {
			return jsObject(map[string]any{
				"ok":    false,
				"error": err.Error(),
			})
		}

		return jsObject(map[string]any{
			"ok":        true,
			"output":    output,
			"supported": webrepl.SupportedSyntaxSummary(),
			"builtins":  webrepl.SupportedBuiltinNames(),
		})
	}))

	js.Global().Set("mutantReplComplete", js.FuncOf(func(this js.Value, args []js.Value) any {
		prefix := ""
		mode := "supported"
		if len(args) >= 1 {
			prefix = args[0].String()
		}
		if len(args) >= 2 {
			mode = args[1].String()
		}

		return jsObject(map[string]any{
			"ok":         true,
			"candidates": repl.CompletionCandidates(prefix, mode),
		})
	}))

	js.Global().Set("mutantReplCompleteLine", js.FuncOf(func(this js.Value, args []js.Value) any {
		line := ""
		mode := "supported"
		if len(args) >= 1 {
			line = args[0].String()
		}
		if len(args) >= 2 {
			mode = args[1].String()
		}

		return jsObject(map[string]any{
			"ok":         true,
			"candidates": repl.CompletionCandidatesForLine(line, mode),
		})
	}))

	js.Global().Set("mutantReplReady", true)

	select {}
}
