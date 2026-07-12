package security

func CorrelateProcessSignals(target RemoteProcessTarget, signals []RemoteProcessSignal) ProcessRiskVerdict {
	score := 0
	for _, signal := range signals {
		if !signal.Detected {
			continue
		}
		if signal.Weight > 0 {
			score += signal.Weight
		}
	}
	if score > 100 {
		score = 100
	}

	return ProcessRiskVerdict{
		PID:        target.PID,
		Name:       target.Name,
		FinalScore: score,
		RiskBand:   riskBandForScore(score),
		Signals:    signals,
	}
}

func riskBandForScore(score int) string {
	switch {
	case score < 40:
		return "low"
	case score < 70:
		return "medium"
	case score < 85:
		return "high"
	default:
		return "critical"
	}
}
