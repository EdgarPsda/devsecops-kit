package report

import (
	"testing"
	"time"
)

func TestEvaluateWithPolicyNoSLAUsesBaseEvaluation(t *testing.T) {
	evaluation := EvaluateWithPolicy([]PolicyFinding{{Finding: Finding{Severity: "LOW"}}}, PolicyConfig{}, time.Now())
	if evaluation.Status != StatusWarn {
		t.Fatalf("expected WARN, got %s", evaluation.Status)
	}
	if evaluation.SLAFailCount != 0 || evaluation.SLAWarnCount != 0 {
		t.Fatalf("expected no SLA counts, got %+v", evaluation)
	}
}

func TestEvaluateWithPolicyWarnsWhenApproachingSLA(t *testing.T) {
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	evaluation := EvaluateWithPolicy([]PolicyFinding{
		{Finding: Finding{Severity: "LOW"}, FirstSeen: now.AddDate(0, 0, -20)},
	}, PolicyConfig{SLA: SLAConfig{Enabled: true, Warn: map[string]int{"LOW": 14}, Fail: map[string]int{"LOW": 30}}}, now)
	if evaluation.Status != StatusWarn {
		t.Fatalf("expected WARN, got %s", evaluation.Status)
	}
	if evaluation.SLAWarnCount != 1 {
		t.Fatalf("expected one SLA warning, got %d", evaluation.SLAWarnCount)
	}
}

func TestEvaluateWithPolicyFailsWhenPastSLA(t *testing.T) {
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	evaluation := EvaluateWithPolicy([]PolicyFinding{
		{Finding: Finding{Severity: "MEDIUM"}, FirstSeen: now.AddDate(0, 0, -91)},
	}, PolicyConfig{SLA: SLAConfig{Enabled: true, Fail: map[string]int{"MEDIUM": 90}}}, now)
	if evaluation.Status != StatusFail {
		t.Fatalf("expected FAIL, got %s", evaluation.Status)
	}
	if evaluation.SLAFailCount != 1 || evaluation.BlockingCount != 1 {
		t.Fatalf("expected one SLA failure/blocking finding, got %+v", evaluation)
	}
}

func TestEvaluateWithPolicyIgnoresFindingsWithoutFirstSeen(t *testing.T) {
	evaluation := EvaluateWithPolicy([]PolicyFinding{{Finding: Finding{Severity: "LOW"}}}, PolicyConfig{SLA: SLAConfig{Enabled: true, Fail: map[string]int{"LOW": 1}}}, time.Now())
	if evaluation.SLAFailCount != 0 {
		t.Fatalf("expected missing first_seen to be ignored, got %+v", evaluation)
	}
}
