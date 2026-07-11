//go:build ignore

package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	patchPath := "examples/lua_sample_patch.lua"
	patchBytes, err := os.ReadFile(patchPath)
	if err != nil {
		fmt.Printf("failed to read %s: %v\n", patchPath, err)
		os.Exit(1)
	}

	http.HandleFunc("/lua_patch.lua", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(patchBytes)
	})

	addr := "127.0.0.1:8080"
	fmt.Printf("serving %s at http://%s/lua_patch.lua\n", patchPath, addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Printf("server failed: %v\n", err)
		os.Exit(1)
	}
}
