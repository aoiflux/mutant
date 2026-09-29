package security

const (
	// defaultRemoteScanHighRisk is the verdict score from which the remote
	// process scan records a process as suspicious, and where its "high" risk
	// band starts. The scan is off in every shipped binary and its Windows
	// scanner returns no verdicts, so only tests, which supply their own
	// verdicts, ever reach these scores.
	//
	//mutant:limit score
	defaultRemoteScanHighRisk = 70
	// defaultRemoteScanCritical is the verdict score from which the scan
	// records a process as critical and, in enforce mode, stops the run; its
	// "critical" band starts here. Like defaultRemoteScanHighRisk, only tests
	// ever reach it.
	//
	//mutant:limit score
	defaultRemoteScanCritical = 85
	// remoteScanMediumScore is where the "medium" risk band starts; below it
	// a verdict is "low". It labels a verdict and decides nothing.
	//
	//mutant:limit score
	remoteScanMediumScore = 40
)

var remoteScanConfigState = RemoteScanConfig{
	Enabled:       false,
	Mode:          RemoteScanModeObserve,
	Allowlist:     map[string]struct{}{},
	HighRiskScore: defaultRemoteScanHighRisk,
	CriticalScore: defaultRemoteScanCritical,
}

func SetRemoteScanConfigForTesting(cfg RemoteScanConfig) {
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
