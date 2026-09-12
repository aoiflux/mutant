# Debugging Mutant programs

`mutant debug` is a [Debug Adapter Protocol](https://microsoft.github.io/debug-adapter-protocol/)
server. An editor starts it, speaks the protocol to it, and shows breakpoints,
stepping, the call stack and variables in its own windows. One implementation
therefore serves VS Code, Neovim's `nvim-dap`, and anything else that speaks
DAP.

It is not an interactive command. Run on its own it waits for a client and does
nothing.

---

## Quick start

### VS Code

The Mutant extension contributes a `mutant` debug type. Open a `.mut` file and
press **F5**. With no `launch.json`, the extension debugs the file in front of
you.

To keep a configuration, add one to `.vscode/launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "mutant",
      "request": "launch",
      "name": "Debug the current Mutant file",
      "program": "${file}",
      "stopOnEntry": false
    }
  ]
}
```

The extension finds the CLI through the `mutant.cli.path` setting, which
defaults to `mutant` on `PATH`.

### Neovim (nvim-dap)

```lua
local dap = require('dap')

dap.adapters.mutant = {
  type = 'executable',
  command = 'mutant',
  args = { 'debug' },
}

dap.configurations.mutant = {
  {
    type = 'mutant',
    request = 'launch',
    name = 'Debug this file',
    program = '${file}',
    stopOnEntry = false,
  },
}
```

### Any other client

`mutant debug` speaks the protocol on stdin and stdout. `mutant debug --port
9000` serves it on a TCP port instead, for clients that would rather not share
a process's stdio. `--host` chooses the interface and defaults to loopback: a
debug session can read every value the program is holding, so it is not
something to expose by accident.

---

## Launch configuration

Every setting arrives in the launch request or on the command line. **Nothing is
read from environment variables** — see [CONFIGURATION_POLICY.md](CONFIGURATION_POLICY.md).

| Field         | Meaning                                                                     |
| ------------- | --------------------------------------------------------------------------- |
| `program`     | The `.mut` to debug. Required.                                              |
| `stopOnEntry` | Stop before the first instruction, so a program can be stepped from the top. |
| `modulePaths` | Directories to search for imported modules, in order. Same as `--module-path`. |
| `noDebug`     | Run without stopping for anything. Output and the exit code still arrive.   |

---

## What you can do

**Breakpoints.** Set them on any line that emitted an instruction. A breakpoint
on a blank line, a comment, or a declaration that compiled to nothing binds
forward to the next line that did, and the editor's marker moves to show where
it landed. A line after the last one with code cannot hold a breakpoint at all,
and is reported unverified with the reason rather than shown as a solid marker
that never fires.

**Hit counts** work: `5` stops on the fifth arrival onwards, `>5` on the sixth.

**Stepping.** Step over, step into and step out, on source lines rather than
instructions — one line is many instructions, and stopping on each would be
useless. Step-over runs any call the current line makes to completion.

**The call stack**, innermost first, each frame naming its function, the
arguments it was called with, and the file and line it is parked on. A stack
that crosses a module boundary names both files.

**Variables**, grouped as Arguments, Locals and Globals. Arrays, hashes and
structs expand; hash keys are shown in sorted order, the same order printing a
hash shows. A local whose declaration has not run yet reads `<unset>` rather
than showing whatever the previous call left in that stack slot.

**Evaluate** answers a plain variable name, in the watch window or the debug
console.

---

## What it deliberately does not do

**It does not attach to a running process.** `mutant debug` *is* the program's
process: it compiles the source, builds a VM, and drives it. A Mutant program
carries anti-debugging probes that terminate a secure-mode run when an OS
debugger is present, so a design that attached one would have the language's own
tooling trip its own tamper response. An `attach` request is refused with a
message naming `launch`.

**It does not debug a `.mu`.** Debugging runs from source. A release artifact
has had every source position stripped from it, so there is nothing to step
through and no name for any slot; an unstripped one is encrypted, which would
put a password prompt in the middle of a handshake the editor owns. This is also
a disclosure boundary: a program that left this machine does not print its own
runtime values back out.

**It does not evaluate expressions.** `total` can be answered; `total * 2`
cannot. Evaluating an expression means compiling it in the frame's scope, and
the scope is the compiler's symbol table, which does not travel in a compiled
program. A debugger that answered anyway would be guessing, and a watch window
is where you go to stop guessing. Conditional breakpoints ride on the same
limit — a condition is an expression. A breakpoint with one stays **armed** and
carries a message saying the condition is ignored, because a breakpoint that
silently never fires is the worse of the two failures.

**It does not step into `spawn` or `pmap`.** Those run their work on sibling
VMs, which have no debugger attached. A closure called back through an ordinary
builtin — `map`, `filter`, `with_resource` — runs on the same VM and is stepped
normally.

**It does not write to variables.** Everything shown is read.

---

## How a debug build differs from a release build

A debug session compiles with **no polymorphic mutation** (`--mutation 0`).
Nothing is being protected in a session whose whole purpose is to watch the
program execute, and every layer removed is a layer that cannot misreport a
position.

Everything else is the same program: the security-check opcodes are still
injected, and values still live encrypted on the stack — the debugger reads them
through the same decryption every other reader goes through. The program you
step is the program that runs.

---

## Troubleshooting

**"this program carries no source positions"** — the program was built for
release, which strips them. Debug the `.mut`.

**The editor cannot find the adapter.** VS Code runs `mutant debug`; set
`mutant.cli.path` if the CLI is not on `PATH`.

**A breakpoint in an imported module does not bind.** The adapter matches the
editor's path against the modules the program was built from, by absolute path
first and by file name second. Two modules with the same file name are
deliberately not guessed between: name the one you mean by opening it from the
path the program imports.

**The program's output.** It arrives as protocol output events, which is what
keeps it off the transport — an adapter whose program wrote to its own stdout
would corrupt every message after the first `putln`. In VS Code it appears in
the Debug Console.

---

## See also

- [EXECUTION_MODES.md](EXECUTION_MODES.md) — what `--secure`, `--compat` and `--dev` change.
- [CONFIGURATION_POLICY.md](CONFIGURATION_POLICY.md) — why nothing here reads an environment variable.
- [MODULES.md](MODULES.md) — how imports resolve, which is what `modulePaths` feeds.
