package security

import "testing"

func TestCorrelateProcessSignalsRiskBandsAndCap(t *testing.T) {
	target := RemoteProcessTarget{PID: 1234, Name: "testproc"}

	cases := []struct {
		name      string
		signals   []RemoteProcessSignal
		wantScore int
		wantBand  string
	}{
		{
			name:      "empty signals low",
			signals:   nil,
			wantScore: 0,
			wantBand:  "low",
		},
		{
			name:      "medium",
			signals:   []RemoteProcessSignal{{Detected: true, Weight: 45}},
			wantScore: 45,
			wantBand:  "medium",
		},
		{
			name:      "high",
			signals:   []RemoteProcessSignal{{Detected: true, Weight: 70}},
			wantScore: 70,
			wantBand:  "high",
		},
		{
			name:      "critical",
			signals:   []RemoteProcessSignal{{Detected: true, Weight: 90}},
			wantScore: 90,
			wantBand:  "critical",
		},
		{
			name:      "cap at 100",
			signals:   []RemoteProcessSignal{{Detected: true, Weight: 70}, {Detected: true, Weight: 50}},
			wantScore: 100,
			wantBand:  "critical",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CorrelateProcessSignals(target, tc.signals)
			if got.FinalScore != tc.wantScore {
				t.Fatalf("score mismatch got=%d want=%d", got.FinalScore, tc.wantScore)
			}
			if got.RiskBand != tc.wantBand {
				t.Fatalf("band mismatch got=%s want=%s", got.RiskBand, tc.wantBand)
			}
		})
	}
}
