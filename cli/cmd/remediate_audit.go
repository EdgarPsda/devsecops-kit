package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/edgarpsda/devsecops-kit/cli/config"
	"github.com/edgarpsda/devsecops-kit/cli/detectors"
)

type remediationAuditReport struct {
	Version        string                   `json:"version"`
	RunID          string                   `json:"run_id"`
	StartedAt      string                   `json:"started_at"`
	FinishedAt     string                   `json:"finished_at,omitempty"`
	Project        remediationAuditProject  `json:"project"`
	Provider       string                   `json:"provider"`
	Scanner        string                   `json:"scanner"`
	OriginalBranch string                   `json:"original_branch,omitempty"`
	Branch         string                   `json:"branch,omitempty"`
	Status         string                   `json:"status"`
	AI             remediationAuditAIConfig `json:"ai"`
	Summary        remediationAuditSummary  `json:"summary"`
	Events         []remediationAuditEvent  `json:"events"`
}

type remediationAuditProject struct {
	Root        string `json:"root"`
	Language    string `json:"language,omitempty"`
	Framework   string `json:"framework,omitempty"`
	PackageFile string `json:"package_file,omitempty"`
}

type remediationAuditAIConfig struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider,omitempty"`
	Model    string `json:"model,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
}

type remediationAuditSummary struct {
	Scanned       int      `json:"scanned"`
	Fixed         int      `json:"fixed"`
	Failed        int      `json:"failed"`
	Remaining     int      `json:"remaining"`
	ModifiedFiles []string `json:"modified_files,omitempty"`
}

type remediationAuditEvent struct {
	Timestamp      string                   `json:"timestamp"`
	Type           string                   `json:"type"`
	Status         string                   `json:"status"`
	Action         string                   `json:"action,omitempty"`
	Method         string                   `json:"method,omitempty"`
	Package        string                   `json:"package,omitempty"`
	Manifest       string                   `json:"manifest,omitempty"`
	Tool           string                   `json:"tool,omitempty"`
	RuleID         string                   `json:"rule_id,omitempty"`
	Severity       string                   `json:"severity,omitempty"`
	File           string                   `json:"file,omitempty"`
	Line           int                      `json:"line,omitempty"`
	FindingIDs     []string                 `json:"finding_ids,omitempty"`
	BeforeFindings int                      `json:"before_findings,omitempty"`
	Resolved       int                      `json:"resolved,omitempty"`
	Remaining      int                      `json:"remaining,omitempty"`
	ModifiedFiles  []string                 `json:"modified_files,omitempty"`
	Reason         string                   `json:"reason,omitempty"`
	AI             *remediationAuditAITrace `json:"ai,omitempty"`
}

type remediationAuditAITrace struct {
	Provider       string `json:"provider,omitempty"`
	Model          string `json:"model,omitempty"`
	PromptSHA256   string `json:"prompt_sha256,omitempty"`
	PromptBytes    int    `json:"prompt_bytes,omitempty"`
	ResponseSHA256 string `json:"response_sha256,omitempty"`
	ResponseBytes  int    `json:"response_bytes,omitempty"`
}

func newRemediationAudit(root, provider, scanner string, secConfig *config.SecurityConfig, projectInfo *detectors.ProjectInfo) *remediationAuditReport {
	now := time.Now().UTC()
	report := &remediationAuditReport{
		Version:   "1",
		RunID:     now.Format("20060102T150405Z"),
		StartedAt: now.Format(time.RFC3339),
		Project: remediationAuditProject{
			Root: root,
		},
		Provider: provider,
		Scanner:  scanner,
		Status:   "running",
		AI: remediationAuditAIConfig{
			Enabled:  secConfig.AI.Enabled,
			Provider: secConfig.AI.Provider,
			Model:    secConfig.AI.Model,
			Endpoint: secConfig.AI.Endpoint,
		},
	}
	if projectInfo != nil {
		report.Project.Language = projectInfo.Language
		report.Project.Framework = projectInfo.Framework
		report.Project.PackageFile = projectInfo.PackageFile
	}
	return report
}

func (r *remediationAuditReport) record(event remediationAuditEvent) {
	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	r.Events = append(r.Events, event)
}

func (r *remediationAuditReport) complete(status string, summary remediationAuditSummary) {
	r.Status = status
	r.Summary = summary
	r.FinishedAt = time.Now().UTC().Format(time.RFC3339)
}

func (r *remediationAuditReport) write(root string) (string, error) {
	if r.FinishedAt == "" {
		r.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	}
	dir := remediationAuditDir(root)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, r.RunID+".json")
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func remediationAuditDir(root string) string {
	base := filepath.Base(filepath.Clean(root))
	if base == "." || base == string(filepath.Separator) || base == "" {
		base = "project"
	}
	projectID := base + "-" + sha256Hex(root)[:12]
	if cacheDir, err := os.UserCacheDir(); err == nil && cacheDir != "" {
		return filepath.Join(cacheDir, "devsecops-kit", "remediation-runs", projectID)
	}
	return filepath.Join(root, ".devsecops", "remediation-runs")
}
func aiTrace(provider, model, prompt, response string) *remediationAuditAITrace {
	return &remediationAuditAITrace{
		Provider:       provider,
		Model:          model,
		PromptSHA256:   sha256Hex(prompt),
		PromptBytes:    len([]byte(prompt)),
		ResponseSHA256: sha256Hex(response),
		ResponseBytes:  len([]byte(response)),
	}
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func writeRemediationAudit(root string, audit *remediationAuditReport) {
	path, err := audit.write(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ Failed to write remediation audit report: %v\n", err)
		return
	}
	fmt.Printf("\nAudit report:\n%s\n", path)
}
