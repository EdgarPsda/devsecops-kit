package report

import "time"

// PolicyConfig defines optional enterprise policy gates for scan results.
type PolicyConfig struct {
	Profile string
	SLA     SLAConfig
}

// SLAConfig defines age-based gates for vulnerability management workflows.
type SLAConfig struct {
	Enabled bool
	Fail    map[string]int
	Warn    map[string]int
}

// PolicyFinding extends normalized findings with optional age metadata.
type PolicyFinding struct {
	Finding
	FirstSeen time.Time
}

// PolicyEvaluation contains scan status plus policy/SLA counters.
type PolicyEvaluation struct {
	Evaluation
	SLAFailCount int
	SLAWarnCount int
}

// EvaluateWithPolicy applies the standard PASS/WARN/FAIL model plus optional SLA policy.
func EvaluateWithPolicy(findings []PolicyFinding, policy PolicyConfig, now time.Time) PolicyEvaluation {
	baseFindings := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		baseFindings = append(baseFindings, finding.Finding)
	}

	base := Evaluate(baseFindings)
	evaluation := PolicyEvaluation{Evaluation: base}
	if len(findings) == 0 || !policy.SLA.Enabled {
		return evaluation
	}

	for _, finding := range findings {
		if finding.FirstSeen.IsZero() {
			continue
		}
		severity := NormalizeSeverity(finding.Severity)
		ageDays := int(now.Sub(finding.FirstSeen).Hours() / 24)
		if threshold, ok := policy.SLA.Fail[severity]; ok && threshold >= 0 && ageDays >= threshold {
			evaluation.SLAFailCount++
			continue
		}
		if threshold, ok := policy.SLA.Warn[severity]; ok && threshold >= 0 && ageDays >= threshold {
			evaluation.SLAWarnCount++
		}
	}

	if evaluation.SLAFailCount > 0 {
		evaluation.Status = StatusFail
		evaluation.BlockingCount += evaluation.SLAFailCount
		return evaluation
	}
	if evaluation.Status == StatusPass && evaluation.SLAWarnCount > 0 {
		evaluation.Status = StatusWarn
	}
	return evaluation
}
