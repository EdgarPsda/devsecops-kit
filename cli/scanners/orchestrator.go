package scanners

import (
	"fmt"
	"sync"
	"time"
)

// Orchestrator coordinates running multiple security scanners
type Orchestrator struct {
	projectDir string
	options    ScanOptions
}

// NewOrchestrator creates a new scanner orchestrator
func NewOrchestrator(projectDir string, options ScanOptions) *Orchestrator {
	return &Orchestrator{
		projectDir: projectDir,
		options:    options,
	}
}

// Run executes all enabled scanners in parallel and aggregates results
func (o *Orchestrator) Run() (*ScanReport, error) {
	report := &ScanReport{
		Timestamp: time.Now().Format(time.RFC3339),
		Results:   make(map[string]*ScanResult),
	}

	// Track which scanners to run
	var wg sync.WaitGroup
	resultsChan := make(chan *ScanResult, 4)
	errsChan := make(chan error, 4)

	// Run Semgrep
	if o.options.EnableSemgrep {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := o.runSemgrep()
			if err != nil {
				errsChan <- fmt.Errorf("semgrep scan failed: %w", err)
				return
			}
			resultsChan <- result
		}()
	}

	// Run Gitleaks
	if o.options.EnableGitleaks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := o.runGitleaks()
			if err != nil {
				errsChan <- fmt.Errorf("gitleaks scan failed: %w", err)
				return
			}
			resultsChan <- result
		}()
	}

	// Run Trivy
	if o.options.EnableTrivy {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := o.runTrivy()
			if err != nil {
				errsChan <- fmt.Errorf("trivy scan failed: %w", err)
				return
			}
			resultsChan <- result
		}()
	}

	// Run License scan
	if o.options.EnableLicenses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := o.runLicenseScan()
			if err != nil {
				errsChan <- fmt.Errorf("license scan failed: %w", err)
				return
			}
			resultsChan <- result
		}()
	}

	// Wait for all scanners to complete
	wg.Wait()
	close(resultsChan)
	close(errsChan)

	// Collect results
	var errors []error
	for result := range resultsChan {
		report.Results[result.Tool] = result
		report.AllFindings = append(report.AllFindings, result.Findings...)
	}

	for err := range errsChan {
		errors = append(errors, err)
	}

	// If any scanner failed critically, return error
	if len(errors) > 0 && len(report.Results) == 0 {
		return nil, fmt.Errorf("all scanners failed: %v", errors)
	}

	// Calculate blocking count based on thresholds
	o.calculateBlockingCount(report)

	// Set overall status
	if report.BlockingCount > 0 {
		report.Status = "FAIL"
	} else {
		report.Status = "PASS"
	}

	return report, nil
}

// calculateBlockingCount determines how many findings exceed thresholds
func (o *Orchestrator) calculateBlockingCount(report *ScanReport) {
	report.BlockingCount = 0

	// Check Gitleaks threshold
	if gitleaks, ok := report.Results["gitleaks"]; ok {
		if threshold, exists := o.options.FailOnThresholds["gitleaks"]; exists && threshold >= 0 {
			if gitleaks.Summary.Total > threshold {
				report.BlockingCount += gitleaks.Summary.Total - threshold
			}
		}
	}

	// Check Semgrep threshold
	if semgrep, ok := report.Results["semgrep"]; ok {
		if threshold, exists := o.options.FailOnThresholds["semgrep"]; exists && threshold >= 0 {
			if semgrep.Summary.Total > threshold {
				report.BlockingCount += semgrep.Summary.Total - threshold
			}
		}
	}

	// Check Trivy thresholds (by severity)
	if trivy, ok := report.Results["trivy"]; ok {
		severities := map[string]string{
			"critical": "trivy_critical",
			"high":     "trivy_high",
			"medium":   "trivy_medium",
			"low":      "trivy_low",
		}

		counts := map[string]int{
			"critical": trivy.Summary.Critical,
			"high":     trivy.Summary.High,
			"medium":   trivy.Summary.Medium,
			"low":      trivy.Summary.Low,
		}

		for severity, configKey := range severities {
			if threshold, exists := o.options.FailOnThresholds[configKey]; exists && threshold >= 0 {
				if count, ok := counts[severity]; ok && count > threshold {
					report.BlockingCount += count - threshold
				}
			}
		}
	}

	// Check License violations threshold
	if licenses, ok := report.Results["licenses"]; ok {
		if threshold, exists := o.options.FailOnThresholds["license_violations"]; exists && threshold >= 0 {
			if licenses.Summary.Total > threshold {
				report.BlockingCount += licenses.Summary.Total - threshold
			}
		}
	}
}
