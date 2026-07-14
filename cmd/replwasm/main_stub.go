//go:build !js || !wasm

package main

import "fmt"

func main() {
	fmt.Println("replwasm target is only available for GOOS=js GOARCH=wasm")
}
