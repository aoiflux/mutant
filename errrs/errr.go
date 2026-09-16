package errrs

import "io"

func PrintParseErrors(out io.Writer, msgs []string) {
	io.WriteString(out, "\n"+nextParserComfortMessage()+"\n\n")
	io.WriteString(out, "parser errors:")
	for _, msg := range msgs {
		io.WriteString(out, "\n\t"+msg+"\t\n")
	}
}

func PrintCompilerError(out io.Writer, msg string) {
	io.WriteString(out, "\n"+nextCompilerComfortMessage()+"\n\n")
	io.WriteString(out, "compiler error:")
	io.WriteString(out, "\n\t"+msg+"\t\n")
}

// PrintMachineTraceback reports a VM failure together with the call stack it
// happened on. traceback is already rendered, one tab-indented frame per line.
//
// "Most recent call first" is stated rather than assumed: both conventions are
// common, and a reader who guesses wrong reads the stack backwards.
func PrintMachineTraceback(out io.Writer, msg, traceback string) {
	PrintMachineError(out, msg)
	if traceback == "" {
		return
	}
	io.WriteString(out, "\ntraceback (most recent call first):\n")
	io.WriteString(out, traceback+"\n")
}

func PrintMachineError(out io.Writer, msg string) {
	io.WriteString(out, "\n"+nextMachineComfortMessage()+"\n\n")
	io.WriteString(out, "vm error:")
	io.WriteString(out, "\n\t"+msg+"\t\n")
}
