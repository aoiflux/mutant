package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"mutant/dap"
	"mutant/global"
)

// handleDebugCommand implements `mutant debug [--port N] [--module-path DIR]
// [file.mut]`.
//
// It is a Debug Adapter Protocol server, not an interactive debugger: an editor
// starts it, speaks the protocol to it, and shows the stepping, the stack and
// the variables in its own windows. One implementation therefore serves VS
// Code, Neovim's nvim-dap, and anything else that speaks DAP.
//
// The program to debug normally arrives in the launch request rather than here,
// because that is where an editor keeps it. Naming one on the command line sets
// a default for a client that has nowhere to put it.
func handleDebugCommand(args []string) int {
	set := flag.NewFlagSet("debug", flag.ContinueOnError)
	port := set.Int("port", 0,
		"Serve the protocol on this TCP port instead of stdin/stdout. 0 means stdio.")
	host := set.String("host", "127.0.0.1",
		"Interface to listen on with --port. Loopback by default: a debug session can read the program's memory.")

	var modulePaths []string
	registerModulePathFlag(set, &modulePaths)

	if err := set.Parse(args[2:]); err != nil {
		return 2
	}

	options := dap.Options{ModulePaths: modulePaths}

	switch rest := set.Args(); len(rest) {
	case 0:
	case 1:
		program, err := filepath.Abs(rest[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "mutant debug: %v\n", err)
			return 1
		}
		if filepath.Ext(program) != global.MutantSourceCodeFileExtention {
			// A .mu is either stripped -- no positions, nothing to step -- or
			// unstripped and encrypted, which would put a password prompt in the
			// middle of a handshake the editor owns. Saying so beats failing
			// later with a message about missing debug info.
			fmt.Fprintf(os.Stderr,
				"mutant debug: %s is not source. Debugging runs from the .mut file, not from compiled bytecode.\n",
				rest[0])
			return 2
		}
		options.Program = program
	default:
		fmt.Fprintln(os.Stderr, "usage: mutant debug [--port N] [--host H] [--module-path DIR] [file.mut]")
		return 2
	}

	if *port != 0 {
		address := net.JoinHostPort(*host, strconv.Itoa(*port))
		if err := dap.ListenAndServe(address, options); err != nil {
			fmt.Fprintf(os.Stderr, "mutant debug: %v\n", err)
			return 1
		}
		return 0
	}

	// Stdio is the default transport and the one every editor supports. The
	// program's own output never reaches this stream: the adapter captures it
	// and republishes it as protocol events, which is what keeps a putln from
	// corrupting the session.
	if err := dap.Serve(os.Stdin, os.Stdout, options); err != nil {
		fmt.Fprintf(os.Stderr, "mutant debug: %v\n", err)
		return 1
	}
	return 0
}

func printDebugHelp() {
	fmt.Print(`mutant debug

Usage:
  mutant debug [options] [file.mut]

Serves the Debug Adapter Protocol so an editor can set breakpoints, step, and
inspect a running Mutant program. It is started by the editor, not by hand: on
its own it waits for a client and does nothing.

The program to debug normally arrives in the editor's launch configuration.
Naming one here sets a default for clients that have nowhere to put it.

Options:
  --port N              Serve on a TCP port instead of stdin/stdout.
  --host H              Interface for --port. Default 127.0.0.1.
  --module-path DIR     Directory to search for imported modules; repeat for
                        more, searched in order.

Notes:
  Debugging runs from source. A .mu built for release carries no source
  positions -- there is nothing to step through -- and an unstripped one is
  encrypted, which would need a password in the middle of the editor's
  handshake.

  The program is compiled with no polymorphic mutation, because nothing is
  being protected in a session whose purpose is to watch it execute.

  Nothing is configured through environment variables. Everything comes from
  these flags or from the launch request. See docs/CONFIGURATION_POLICY.md.

  The debugger runs the program in this process rather than attaching to
  another one, so it does not trip the anti-debugging probes a Mutant program
  carries.

VS Code:
  The Mutant extension contributes a "mutant" debug type; press F5 on a .mut.

Neovim (nvim-dap):
  require('dap').adapters.mutant = {
    type = 'executable', command = 'mutant', args = { 'debug' },
  }
  require('dap').configurations.mutant = {{
    type = 'mutant', request = 'launch', name = 'Debug this file',
    program = '${file}', stopOnEntry = false,
  }}
`)
}
