package security

import "fmt"

var scanRemoteProcesses = ScanRemoteProcessesWindows

func RunRemoteProcessScan(stage string) ([]ProcessRiskVerdict, bool, error) {
	cfg := ResolveRemoteScanConfig()
	if !cfg.Enabled || cfg.Mode == RemoteScanModeOff {
		return nil, false, nil
	}

	RecordRemoteProcessScanInvoked(stage)
	verdicts, err := scanRemoteProcesses(cfg)
	if err != nil {
		RecordRemoteProcessScanError(stage)
		return nil, true, err
	}

	normalized := normalizeRemoteProcessVerdicts(verdicts)
	for _, verdict := range normalized {
		scanStage := fmt.Sprintf("%s pid=%d name=%s score=%d band=%s", stage, verdict.PID, verdict.Name, verdict.FinalScore, verdict.RiskBand)
		if verdict.FinalScore >= cfg.CriticalScore {
			RecordRemoteProcessCritical(scanStage)
			continue
		}
		if verdict.FinalScore >= cfg.HighRiskScore {
			RecordRemoteProcessSuspicious(scanStage)
		}
	}

	return normalized, true, nil
}

func normalizeRemoteProcessVerdicts(verdicts []ProcessRiskVerdict) []ProcessRiskVerdict {
	if len(verdicts) == 0 {
		return verdicts
	}

	normalized := make([]ProcessRiskVerdict, 0, len(verdicts))
	for _, verdict := range verdicts {
		target := RemoteProcessTarget{PID: verdict.PID, Name: verdict.Name}
		if len(verdict.Signals) > 0 {
			nv := CorrelateProcessSignals(target, verdict.Signals)
			normalized = append(normalized, nv)
			continue
		}
		verdict.RiskBand = riskBandForScore(verdict.FinalScore)
		normalized = append(normalized, verdict)
	}

	return normalized
}
