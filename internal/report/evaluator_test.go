package report

import "testing"

func TestEvaluateNoFindingsPass(t *testing.T) {
	evaluation := Evaluate(nil)
	if evaluation.Status != StatusPass {
		t.Fatalf("expected PASS, got %s", evaluation.Status)
	}
	if evaluation.BlockingCount != 0 {
		t.Fatalf("expected no blocking findings, got %d", evaluation.BlockingCount)
	}
}

func TestEvaluateLowWarn(t *testing.T) {
	evaluation := Evaluate([]Finding{{Severity: "LOW"}})
	if evaluation.Status != StatusWarn {
		t.Fatalf("expected WARN, got %s", evaluation.Status)
	}
}

func TestEvaluateMediumWarn(t *testing.T) {
	evaluation := Evaluate([]Finding{{Severity: "MEDIUM"}})
	if evaluation.Status != StatusWarn {
		t.Fatalf("expected WARN, got %s", evaluation.Status)
	}
}

func TestEvaluateHighFail(t *testing.T) {
	evaluation := Evaluate([]Finding{{Severity: "HIGH"}})
	if evaluation.Status != StatusFail {
		t.Fatalf("expected FAIL, got %s", evaluation.Status)
	}
	if evaluation.BlockingCount != 1 {
		t.Fatalf("expected one blocking finding, got %d", evaluation.BlockingCount)
	}
}

func TestEvaluateCriticalFail(t *testing.T) {
	evaluation := Evaluate([]Finding{{Severity: "CRITICAL"}})
	if evaluation.Status != StatusFail {
		t.Fatalf("expected FAIL, got %s", evaluation.Status)
	}
}

func TestEvaluateExplicitBlockingFail(t *testing.T) {
	evaluation := Evaluate([]Finding{{Severity: "LOW", Blocking: true}})
	if evaluation.Status != StatusFail {
		t.Fatalf("expected FAIL, got %s", evaluation.Status)
	}
}
