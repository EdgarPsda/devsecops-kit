package report

import "strings"

const (
	StatusPass = "PASS"
	StatusWarn = "WARN"
	StatusFail = "FAIL"
)

// Finding contains normalized data needed to evaluate scan status.
type Finding struct {
	Tool     string
	Severity string
	Blocking bool
	Rule     string
	File     string
	Line     int
}

// Evaluation contains the global scan status and blocking count.
type Evaluation struct {
	Status        string
	BlockingCount int
}

// Evaluate calculates the global scan status from normalized findings.
func Evaluate(findings []Finding) Evaluation {
	if len(findings) == 0 {
		return Evaluation{Status: StatusPass}
	}

	blockingCount := 0
	for _, finding := range findings {
		if isBlocking(finding) {
			blockingCount++
		}
	}

	if blockingCount > 0 {
		return Evaluation{
			Status:        StatusFail,
			BlockingCount: blockingCount,
		}
	}

	return Evaluation{Status: StatusWarn}
}

func isBlocking(finding Finding) bool {
	if finding.Blocking {
		return true
	}

	switch NormalizeSeverity(finding.Severity) {
	case "CRITICAL", "HIGH":
		return true
	default:
		return false
	}
}

// NormalizeSeverity maps scanner-specific severities into the internal model.
func NormalizeSeverity(severity string) string {
	s := strings.ToUpper(strings.TrimSpace(severity))
	switch s {
	case "CRITICAL", "CRITICAL,HIGH", "FATAL":
		return "CRITICAL"
	case "ERROR", "HIGH":
		return "HIGH"
	case "WARNING", "WARN", "MEDIUM", "MODERATE":
		return "MEDIUM"
	case "LOW", "INFO", "INFORMATIONAL", "NOTE":
		return "LOW"
	default:
		return "MEDIUM"
	}
}
