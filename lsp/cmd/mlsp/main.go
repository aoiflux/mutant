package main

import (
	"flag"
	"fmt"
	"os"

	"mutant/builtin"
	"mutant/global"
	lspserver "mutant/lsp/internal/server"
)

func main() {
	debug := flag.Bool("debug", false, "enable verbose server logging")
	version := flag.Bool("version", false, "print the language version this server was built from, then exit")
	flag.Parse()

	// This binary ships inside the extension, built from a checkout that can be
	// older than the language it is asked to teach. What goes stale is the
	// release it was cut from and the builtin registry it linked, so it reports
	// both: an editor behind the language becomes something an examiner can
	// see, and something the packaging gate can compare against source.
	if *version {
		fmt.Printf("mlsp %s (%d builtins)\n", global.Version, len(builtin.Builtins))
		return
	}

	server := lspserver.New(*debug)
	if err := server.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "mlsp: %v\n", err)
		os.Exit(1)
	}
}
