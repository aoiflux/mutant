//go:build js && wasm

package main

import (
	"mutant/webrepl"
	"syscall/js"
)

func main() {
	repl := webrepl.New()

	js.Global().Set("mutantReplEval", js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return map[string]any{
				"ok":    false,
				"error": "mutantReplEval expects one argument",
			}
		}

		input := args[0].String()
		output, err := repl.Eval(input)
		if err != nil {
			return map[string]any{
				"ok":    false,
				"error": err.Error(),
			}
		}

		return map[string]any{
			"ok":        true,
			"output":    output,
			"supported": webrepl.SupportedSyntaxSummary(),
		}
	}))

	js.Global().Set("mutantReplReady", true)

	select {}
}
