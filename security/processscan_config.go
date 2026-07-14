package security

import (
	"strings"
)

const (
	defaultRemoteScanMaxProcesses = 32
	defaultRemoteScanIntervalMs   = 1000
	defaultRemoteScanHighRisk     = 70
	defaultRemoteScanCritical     = 85
)

var remoteScanConfigState = RemoteScanConfig{
	Enabled:       false,
	Mode:          RemoteScanModeObserve,
	MaxProcesses:  defaultRemoteScanMaxProcesses,
	IntervalMs:    defaultRemoteScanIntervalMs,
	Allowlist:     map[string]struct{}{},
	HighRiskScore: defaultRemoteScanHighRisk,
	CriticalScore: defaultRemoteScanCritical,
}

func SetRemoteScanConfigForTesting(cfg RemoteScanConfig) {
	if cfg.MaxProcesses <= 0 {
		cfg.MaxProcesses = defaultRemoteScanMaxProcesses
	}
	if cfg.IntervalMs <= 0 {
		cfg.IntervalMs = defaultRemoteScanIntervalMs
	}
	if cfg.HighRiskScore <= 0 {
		cfg.HighRiskScore = defaultRemoteScanHighRisk
	}
	if cfg.CriticalScore <= 0 {
		cfg.CriticalScore = defaultRemoteScanCritical
	}
	if cfg.Allowlist == nil {
		cfg.Allowlist = map[string]struct{}{}
	}
	if cfg.Mode != RemoteScanModeOff && cfg.Mode != RemoteScanModeObserve && cfg.Mode != RemoteScanModeEnforce {
		cfg.Mode = RemoteScanModeObserve
	}
	remoteScanConfigState = cfg
}

func ResetRemoteScanConfigForTesting() {
	remoteScanConfigState = RemoteScanConfig{
		Enabled:       false,
		Mode:          RemoteScanModeObserve,
		MaxProcesses:  defaultRemoteScanMaxProcesses,
		IntervalMs:    defaultRemoteScanIntervalMs,
		Allowlist:     map[string]struct{}{},
		HighRiskScore: defaultRemoteScanHighRisk,
		CriticalScore: defaultRemoteScanCritical,
	}
}

func ResolveRemoteScanConfig() RemoteScanConfig {
	cfg := remoteScanConfigState
	if cfg.Mode != RemoteScanModeOff && cfg.Mode != RemoteScanModeObserve && cfg.Mode != RemoteScanModeEnforce {
		cfg.Mode = RemoteScanModeObserve
	}
	if cfg.Allowlist == nil {
		cfg.Allowlist = map[string]struct{}{}
	}
	if cfg.CriticalScore < cfg.HighRiskScore {
		cfg.CriticalScore = cfg.HighRiskScore
	}
	return cfg
}

func isRemoteProcessScanEnabled() bool {
	return remoteScanConfigState.Enabled
}

func resolveRemoteProcessScanMode() string {
	return remoteScanConfigState.Mode
}

func parseRemoteProcessAllowlist() map[string]struct{} {
	allow := map[string]struct{}{}
	raw := ""
	if raw == "" {
		return allow
	}
	for _, part := range strings.Split(raw, ",") {
		name := strings.TrimSpace(strings.ToLower(part))
		if name == "" {
			continue
		}
		allow[name] = struct{}{}
	}
	return allow
}
