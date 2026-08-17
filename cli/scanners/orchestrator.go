package scanners

import (
	"fmt"
	"sync"
	"time"

	scanreport "github.com/edgarpsda/devsecops-kit/internal/report"
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
	resultsChan := make(chan *ScanResult, 5)
	errsChan := make(chan error, 5)

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

	// Run Checkov
	if o.options.EnableCheckov {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := o.runCheckov()
			if err != nil {
				errsChan <- fmt.Errorf("checkov scan failed: %w", err)
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

	o.evaluateStatus(report, len(errors) > 0)

	return report, nil
}

func (o *Orchestrator) evaluateStatus(report *ScanReport, hasScannerErrors bool) {
	findings := make([]scanreport.Finding, 0, len(report.AllFindings))
	for _, finding := range report.AllFindings {
		findings = append(findings, scanreport.Finding{
			Tool:     finding.Tool,
			Severity: finding.Severity,
			Blocking: finding.Blocking,
			Rule:     finding.RuleID,
			File:     finding.File,
			Line:     finding.Line,
		})
	}

	evaluation := scanreport.Evaluate(findings)
	report.Status = evaluation.Status
	report.BlockingCount = evaluation.BlockingCount

	if hasScannerErrors && report.Status == scanreport.StatusPass {
		report.Status = scanreport.StatusFail
	}
}
