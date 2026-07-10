package main

import (
	"flag"
	"fmt"
	"os"

	lspserver "mutant/lsp/internal/server"
)

func main() {
	debug := flag.Bool("debug", false, "enable verbose server logging")
	flag.Parse()

	server := lspserver.New(*debug)
	if err := server.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "mlsp: %v\n", err)
		os.Exit(1)
	}
}
