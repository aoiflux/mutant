package security

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	CommandExecEnabledEnv      = "MUTANT_ENABLE_COMMAND_EXEC"
	CommandExecAllowedShells   = "MUTANT_COMMAND_EXEC_ALLOWED_SHELLS"
	CommandExecTimeoutMsEnv    = "MUTANT_COMMAND_EXEC_TIMEOUT_MS"
	CommandExecMaxOutputBytes  = "MUTANT_COMMAND_EXEC_MAX_OUTPUT_BYTES"
	defaultCommandExecTimeout  = 3000
	defaultCommandMaxOutput    = 8192
	minimumCommandExecTimeout  = 100
	maximumCommandExecTimeout  = 60000
	minimumCommandMaxOutput    = 256
	maximumCommandMaxOutput    = 1048576
	defaultAllowedShellsConfig = "powershell,cmd"

	policyBlockedEmpty    = "blocked_empty"
	policyBlockedDisabled = "blocked_disabled"
	policyBlockedShell    = "blocked_shell"
	policyAllowed         = "allowed"

	errorCommandEmpty     = "command is empty"
	errorCommandDisabled  = "command execution disabled"
	errorCommandTimedOut  = "command timed out"
	truncatedOutputSuffix = "\n...[truncated]"

	defaultShellName = "powershell"
	shellPowerShell  = "powershell"
	shellPwsh        = "pwsh"
	shellCmd         = "cmd"
	shellBatch       = "batch"

	powershellExecutable = "powershell.exe"
	cmdExecutable        = "cmd.exe"
	cmdFlagExec          = "/C"

	pwshFlagNoLogo         = "-NoLogo"
	pwshFlagNoProfile      = "-NoProfile"
	pwshFlagNonInteractive = "-NonInteractive"
	pwshFlagCommand        = "-Command"
)

type CommandResult struct {
	Allowed        bool
	PolicyDecision string
	ExitCode       int
	Stdout         string
	Stderr         string
	TimedOut       bool
	ErrorMessage   string
}

func ExecuteCommand(shell, command, stage string) CommandResult {
	RecordCommandAttempt(stage)

	trimmedCommand := strings.TrimSpace(command)
	if trimmedCommand == "" {
		RecordCommandBlocked(stage)
		return CommandResult{
			Allowed:        false,
			PolicyDecision: policyBlockedEmpty,
			ErrorMessage:   errorCommandEmpty,
		}
	}

	if strings.TrimSpace(os.Getenv(CommandExecEnabledEnv)) != "1" {
		RecordCommandBlocked(stage)
		return CommandResult{
			Allowed:        false,
			PolicyDecision: policyBlockedDisabled,
			ErrorMessage:   errorCommandDisabled,
		}
	}

	normalizedShell := normalizeShell(shell)
	execName, execArgs, err := buildShellCommand(normalizedShell, trimmedCommand)
	if err != nil {
		RecordCommandBlocked(stage)

		return CommandResult{
			Allowed:        false,
			PolicyDecision: policyBlockedShell,
			ErrorMessage:   err.Error(),
		}
	}

	timeout := resolveCommandExecTimeout()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, execName, execArgs...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	result := CommandResult{
		Allowed:        true,
		PolicyDecision: policyAllowed,

		ExitCode: 0,
		Stdout:   truncateOutput(stdout.String(), resolveCommandExecMaxOutput()),
		Stderr:   truncateOutput(stderr.String(), resolveCommandExecMaxOutput()),
	}

	if ctx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		result.ErrorMessage = errorCommandTimedOut
		result.ExitCode = -1
		RecordCommandFailed(stage)
		return result
	}

	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
		result.ErrorMessage = runErr.Error()
		RecordCommandFailed(stage)
		return result
	}

	RecordCommandSucceeded(stage)

	return result
}

func normalizeShell(shell string) string {
	normalized := strings.ToLower(strings.TrimSpace(shell))
	if normalized == "" {
		return defaultShellName
	}
	return normalized
}

func buildShellCommand(shell, command string) (string, []string, error) {
	switch shell {
	case shellPowerShell, shellPwsh:
		return powershellExecutable, []string{pwshFlagNoLogo, pwshFlagNoProfile, pwshFlagNonInteractive, pwshFlagCommand, command}, nil
	case shellCmd, shellBatch:
		return cmdExecutable, []string{cmdFlagExec, command}, nil
	default:
		return "", nil, fmt.Errorf("unsupported shell %q", shell)
	}
}

func resolveCommandExecTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv(CommandExecTimeoutMsEnv))
	if raw == "" {
		return time.Duration(defaultCommandExecTimeout) * time.Millisecond
	}

	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return time.Duration(defaultCommandExecTimeout) * time.Millisecond
	}
	if parsed < minimumCommandExecTimeout {
		parsed = minimumCommandExecTimeout
	}
	if parsed > maximumCommandExecTimeout {
		parsed = maximumCommandExecTimeout
	}
	return time.Duration(parsed) * time.Millisecond
}

func resolveCommandExecMaxOutput() int {
	raw := strings.TrimSpace(os.Getenv(CommandExecMaxOutputBytes))
	if raw == "" {
		return defaultCommandMaxOutput
	}

	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return defaultCommandMaxOutput
	}
	if parsed < minimumCommandMaxOutput {
		parsed = minimumCommandMaxOutput
	}
	if parsed > maximumCommandMaxOutput {
		parsed = maximumCommandMaxOutput
	}
	return parsed
}

func truncateOutput(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit] + truncatedOutputSuffix
}
