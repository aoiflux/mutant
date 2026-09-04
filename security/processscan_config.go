package security

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

// parseRemoteProcessAllowlist returns the set of process names exempt from the
// remote scan. There is no allowlist source today: the env variable it used to
// parse is gone, and no flag has replaced it, so the set is always empty. Kept
// as the single seam a future --scan-allowlist file would fill.
// See docs/CONFIGURATION_POLICY.md.
func parseRemoteProcessAllowlist() map[string]struct{} {
	return map[string]struct{}{}
}
