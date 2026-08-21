package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/edgarpsda/devsecops-kit/cli/ai"
	"github.com/edgarpsda/devsecops-kit/cli/config"
	"github.com/edgarpsda/devsecops-kit/cli/detectors"
)

type snykScanResult struct {
	ProjectName       string              `json:"projectName"`
	Path              string              `json:"path"`
	DisplayTargetFile string              `json:"displayTargetFile"`
	PackageManager    string              `json:"packageManager"`
	TargetFile        string              `json:"targetFile"`
	Vulnerabilities   []snykVulnerability `json:"vulnerabilities"`
}

type snykVulnerability struct {
	ID                    string          `json:"id"`
	Title                 string          `json:"title"`
	Severity              string          `json:"severity"`
	PackageName           string          `json:"packageName"`
	Name                  string          `json:"name"`
	Version               string          `json:"version"`
	PackageManager        string          `json:"packageManager"`
	IsUpgradable          bool            `json:"isUpgradable"`
	IsPatchable           bool            `json:"isPatchable"`
	UpgradePath           []interface{}   `json:"upgradePath"`
	NearestFixedInVersion string          `json:"nearestFixedInVersion"`
	FixedIn               []string        `json:"fixedIn"`
	From                  []string        `json:"from"`
	Identifiers           json.RawMessage `json:"identifiers"`
	Description           string          `json:"description"`
	Recommendation        string          `json:"recommendation"`
	ProjectName           string          `json:"-"`
	ProjectPath           string          `json:"-"`
	TargetFile            string          `json:"-"`
	ManifestFile          string          `json:"-"`
}

type snykRemediationGroup struct {
	ManifestFile string
	PackageName  string
	Findings     []snykVulnerability
}

func runSnykRemediationMVP(dir string, secConfig *config.SecurityConfig) error {
	if _, err := exec.LookPath("snyk"); err != nil {
		return fmt.Errorf("snyk is not installed or not on PATH")
	}

	projectInfo, err := detectors.DetectProject(dir)
	if err != nil {
		return fmt.Errorf("failed to detect project: %w", err)
	}

	if !secConfig.AI.Enabled {
		return fmt.Errorf("Snyk remediation requires ai.enabled=true in %s", remediateConfigPath)
	}
	if err := config.ValidateAIConfig(secConfig.AI); err != nil {
		return err
	}

	aiClient := ai.NewClient(ai.Config{
		Enabled:  true,
		Provider: secConfig.AI.Provider,
		Model:    secConfig.AI.Model,
		Endpoint: secConfig.AI.Endpoint,
		APIKey:   aiAPIKey(secConfig),
	})
	audit := newRemediationAudit(dir, "snyk", "snyk", secConfig, projectInfo)

	fmt.Println("🔍 Running Snyk scan...")
	findings, err := runSnykScan(dir)
	if err != nil {
		audit.complete("failed", remediationAuditSummary{})
		audit.record(remediationAuditEvent{Type: "scan", Status: "failed", Reason: err.Error()})
		writeRemediationAudit(dir, audit)
		return err
	}
	targets := snykHighCritical(findings)
	audit.Summary.Scanned = len(findings)
	audit.record(remediationAuditEvent{Type: "scan", Status: "completed", Action: "snyk test", BeforeFindings: len(targets)})
	if len(targets) == 0 {
		fmt.Println("✅ No HIGH or CRITICAL Snyk vulnerabilities found. Nothing to remediate.")
		audit.complete("passed", remediationAuditSummary{Scanned: len(findings)})
		writeRemediationAudit(dir, audit)
		return nil
	}

	originalBranch, err := gitOutput(dir, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		audit.complete("failed", remediationAuditSummary{Scanned: len(findings)})
		audit.record(remediationAuditEvent{Type: "git", Status: "failed", Action: "detect current branch", Reason: err.Error()})
		writeRemediationAudit(dir, audit)
		return fmt.Errorf("failed to detect current git branch: %w", err)
	}
	audit.OriginalBranch = originalBranch

	if dirty, err := gitHasChanges(dir); err != nil {
		audit.complete("failed", remediationAuditSummary{Scanned: len(findings)})
		audit.record(remediationAuditEvent{Type: "git", Status: "failed", Action: "inspect working tree", Reason: err.Error()})
		writeRemediationAudit(dir, audit)
		return err
	} else if dirty {
		reason := "working tree has existing changes; commit, stash, or clean them before auto remediation"
		audit.complete("failed", remediationAuditSummary{Scanned: len(findings)})
		audit.record(remediationAuditEvent{Type: "git", Status: "failed", Action: "inspect working tree", Reason: reason})
		writeRemediationAudit(dir, audit)
		return fmt.Errorf("%s", reason)
	}

	fmt.Println("🧪 Running baseline project validation...")
	if err := runProjectTests(dir, projectInfo); err != nil {
		audit.complete("failed", remediationAuditSummary{Scanned: len(findings)})
		audit.record(remediationAuditEvent{Type: "validation", Status: "failed", Action: "baseline tests", Reason: err.Error()})
		writeRemediationAudit(dir, audit)
		return fmt.Errorf("baseline validation failed; fix the project tests before auto remediation:\n%w", err)
	}
	audit.record(remediationAuditEvent{Type: "validation", Status: "passed", Action: "baseline tests"})

	branchName := "security/remediation-" + time.Now().Format("20060102-150405")
	if _, err := gitOutput(dir, "checkout", "-b", branchName); err != nil {
		audit.complete("failed", remediationAuditSummary{Scanned: len(findings)})
		audit.record(remediationAuditEvent{Type: "git", Status: "failed", Action: "create remediation branch", Reason: err.Error()})
		writeRemediationAudit(dir, audit)
		return fmt.Errorf("failed to create remediation branch: %w", err)
	}
	audit.Branch = branchName
	audit.record(remediationAuditEvent{Type: "git", Status: "completed", Action: "create remediation branch"})

	modified := make(map[string]bool)
	fixed := 0
	failed := 0
	currentFindings := findings
	groups := groupSnykFindings(targets)

	for _, group := range groups {
		if !snykGroupStillPresent(group, currentFindings) {
			fmt.Printf("\n⏭ Skipping %s in %s; already resolved by an earlier change.\n", group.PackageName, group.ManifestFile)
			audit.record(remediationAuditEvent{
				Type:       "remediation_group",
				Status:     "skipped",
				Action:     "already resolved by earlier change",
				Package:    group.PackageName,
				Manifest:   group.ManifestFile,
				FindingIDs: snykGroupFindingIDs(group),
			})
			continue
		}

		finding := group.Findings[0]
		beforeCount := snykGroupPresentCount(group, currentFindings)
		fmt.Printf("\n🛠 Remediating %s in %s (%d HIGH/CRITICAL findings)\n", group.PackageName, group.ManifestFile, beforeCount)

		contextText, err := snykManifestContext(dir, finding)
		if err != nil {
			failed += beforeCount
			audit.record(remediationAuditEvent{
				Type:           "remediation_group",
				Status:         "failed",
				Action:         "read manifest context",
				Package:        group.PackageName,
				Manifest:       group.ManifestFile,
				FindingIDs:     snykGroupFindingIDs(group),
				BeforeFindings: beforeCount,
				Reason:         err.Error(),
			})
			fmt.Printf("❌ Failed to read manifest context: %v\n", err)
			continue
		}

		method := "dependency_fallback"
		var aiAudit *remediationAuditAITrace
		backups, err := applySnykDependencyFallback(dir, group)
		if err != nil {
			fmt.Printf("⚠ Deterministic dependency fallback was not available, trying AI patch: %v\n", err)
			method = "ai_patch"
			prompt := buildSnykGroupRemediationPrompt(projectInfo, group, contextText)
			response, aiErr := aiClient.Complete(prompt)
			if aiErr != nil {
				failed += beforeCount
				audit.record(remediationAuditEvent{
					Type:           "remediation_group",
					Status:         "failed",
					Action:         "generate AI patch",
					Method:         method,
					Package:        group.PackageName,
					Manifest:       group.ManifestFile,
					FindingIDs:     snykGroupFindingIDs(group),
					BeforeFindings: beforeCount,
					Reason:         aiErr.Error(),
				})
				fmt.Printf("❌ AI provider failed: %v\n", aiErr)
				continue
			}
			aiAudit = aiTrace(secConfig.AI.Provider, secConfig.AI.Model, prompt, response)
			backups, err = applyAIPatchWithRepair(dir, aiClient, prompt, response)
			if err != nil {
				failed += beforeCount
				audit.record(remediationAuditEvent{
					Type:           "remediation_group",
					Status:         "failed",
					Action:         "apply patch",
					Method:         method,
					Package:        group.PackageName,
					Manifest:       group.ManifestFile,
					FindingIDs:     snykGroupFindingIDs(group),
					BeforeFindings: beforeCount,
					Reason:         err.Error(),
					AI:             aiAudit,
				})
				fmt.Printf("❌ Failed to apply patch: %v\n", err)
				continue
			}
		}

		modifiedFiles, err := gitChangedFiles(dir)
		if err != nil {
			_ = restoreBackups(backups)
			failed += beforeCount
			audit.record(remediationAuditEvent{
				Type:           "remediation_group",
				Status:         "failed",
				Action:         "detect modified files",
				Method:         method,
				Package:        group.PackageName,
				Manifest:       group.ManifestFile,
				FindingIDs:     snykGroupFindingIDs(group),
				BeforeFindings: beforeCount,
				Reason:         err.Error(),
				AI:             aiAudit,
			})
			fmt.Printf("❌ Failed to detect modified files: %v\n", err)
			continue
		}

		fmt.Println("🧪 Running project validation...")
		if err := runValidationForFiles(dir, projectInfo, modifiedFiles); err != nil {
			_ = restoreBackups(backups)
			failed += beforeCount
			audit.record(remediationAuditEvent{
				Type:           "validation",
				Status:         "failed",
				Action:         "project validation",
				Method:         method,
				Package:        group.PackageName,
				Manifest:       group.ManifestFile,
				FindingIDs:     snykGroupFindingIDs(group),
				BeforeFindings: beforeCount,
				ModifiedFiles:  modifiedFiles,
				Reason:         err.Error(),
				AI:             aiAudit,
			})
			fmt.Printf("❌ Build/tests failed. Changes restored: %v\n", err)
			continue
		}

		fmt.Println("🔁 Re-running Snyk...")
		rescan, err := runSnykScan(dir)
		if err != nil {
			_ = restoreBackups(backups)
			failed += beforeCount
			audit.record(remediationAuditEvent{
				Type:           "rescan",
				Status:         "failed",
				Action:         "snyk test",
				Method:         method,
				Package:        group.PackageName,
				Manifest:       group.ManifestFile,
				FindingIDs:     snykGroupFindingIDs(group),
				BeforeFindings: beforeCount,
				ModifiedFiles:  modifiedFiles,
				Reason:         err.Error(),
				AI:             aiAudit,
			})
			fmt.Printf("❌ Snyk re-scan failed. Changes restored: %v\n", err)
			continue
		}
		currentFindings = rescan

		remainingInGroup := snykGroupPresentCount(group, rescan)
		resolved := beforeCount - remainingInGroup
		if remainingInGroup > 0 {
			if resolved == 0 {
				_ = restoreBackups(backups)
				failed += beforeCount
				audit.record(remediationAuditEvent{
					Type:           "remediation_group",
					Status:         "failed",
					Action:         "verify remediation",
					Method:         method,
					Package:        group.PackageName,
					Manifest:       group.ManifestFile,
					FindingIDs:     snykGroupFindingIDs(group),
					BeforeFindings: beforeCount,
					Remaining:      remainingInGroup,
					ModifiedFiles:  modifiedFiles,
					Reason:         "finding still present after remediation",
					AI:             aiAudit,
				})
				fmt.Printf("❌ %d finding(s) still present for %s. Changes restored.\n", remainingInGroup, group.PackageName)
				continue
			}
			fixed += resolved
			failed += remainingInGroup
			for _, file := range modifiedFiles {
				modified[file] = true
			}
			audit.record(remediationAuditEvent{
				Type:           "remediation_group",
				Status:         "partial",
				Action:         "verify remediation",
				Method:         method,
				Package:        group.PackageName,
				Manifest:       group.ManifestFile,
				FindingIDs:     snykGroupFindingIDs(group),
				BeforeFindings: beforeCount,
				Resolved:       resolved,
				Remaining:      remainingInGroup,
				ModifiedFiles:  modifiedFiles,
				AI:             aiAudit,
			})
			fmt.Printf("⚠ Fixed %d finding(s) for %s; %d remain.\n", resolved, group.PackageName, remainingInGroup)
			continue
		}

		fixed += resolved
		for _, file := range modifiedFiles {
			modified[file] = true
		}
		audit.record(remediationAuditEvent{
			Type:           "remediation_group",
			Status:         "fixed",
			Action:         "verify remediation",
			Method:         method,
			Package:        group.PackageName,
			Manifest:       group.ManifestFile,
			FindingIDs:     snykGroupFindingIDs(group),
			BeforeFindings: beforeCount,
			Resolved:       resolved,
			ModifiedFiles:  modifiedFiles,
			AI:             aiAudit,
		})
		fmt.Printf("✅ Fixed %d finding(s) for %s.\n", resolved, group.PackageName)
	}

	remaining := 0
	if finalFindings, err := runSnykScan(dir); err == nil {
		remaining = len(snykHighCritical(finalFindings))
		fixed = len(targets) - remaining
		if fixed < 0 {
			fixed = 0
		}
		failed = remaining
		audit.record(remediationAuditEvent{Type: "rescan", Status: "completed", Action: "final snyk test", Remaining: remaining})
	} else {
		audit.record(remediationAuditEvent{Type: "rescan", Status: "failed", Action: "final snyk test", Reason: err.Error()})
	}

	finalBranch := branchName
	if fixed == 0 {
		_, _ = gitOutput(dir, "checkout", originalBranch)
		_, _ = gitOutput(dir, "branch", "-D", branchName)
		finalBranch = "(deleted - no successful fixes)"
	}

	modifiedFiles := sortedMapKeys(modified)
	audit.Branch = finalBranch
	audit.complete("completed", remediationAuditSummary{
		Scanned:       len(findings),
		Fixed:         fixed,
		Failed:        failed,
		Remaining:     remaining,
		ModifiedFiles: modifiedFiles,
	})
	writeRemediationAudit(dir, audit)

	printRemediationSummary(len(findings), fixed, failed, modifiedFiles, remaining, finalBranch)
	return nil
}

func runSnykScan(dir string) ([]snykVulnerability, error) {
	cmd := exec.Command("snyk", "test", "--json", "--severity-threshold=high", "--show-vulnerable-paths=all", "--all-projects")
	cmd.Dir = dir

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			switch exitErr.ExitCode() {
			case 1:
				// Snyk returns 1 when vulnerabilities are found.
			default:
				return nil, fmt.Errorf("snyk scan failed: %w\nstderr:\n%s", err, stderr.String())
			}
		} else {
			return nil, fmt.Errorf("snyk scan failed: %w\nstderr:\n%s", err, stderr.String())
		}
	}

	results, err := parseSnykResults(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("unable to parse Snyk JSON output: %w\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	var findings []snykVulnerability
	for _, result := range results {
		for _, vuln := range result.Vulnerabilities {
			if vuln.PackageName == "" {
				vuln.PackageName = vuln.Name
			}
			if vuln.PackageManager == "" {
				vuln.PackageManager = result.PackageManager
			}
			vuln.ProjectName = result.ProjectName
			vuln.ProjectPath = result.Path
			vuln.TargetFile = snykTargetFile(result)
			vuln.ManifestFile = snykManifestFile(dir, result)
			findings = append(findings, vuln)
		}
	}
	return findings, nil
}

func parseSnykResults(data []byte) ([]snykScanResult, error) {
	payload, err := jsonPayload(data)
	if err != nil {
		return nil, err
	}

	var multi []snykScanResult
	if err := json.Unmarshal(payload, &multi); err == nil {
		return multi, nil
	}

	var single snykScanResult
	if err := json.Unmarshal(payload, &single); err == nil {
		return []snykScanResult{single}, nil
	}

	return nil, fmt.Errorf("unrecognized Snyk JSON shape")
}

func jsonPayload(output []byte) ([]byte, error) {
	output = bytes.TrimSpace(output)
	if len(output) == 0 {
		return nil, fmt.Errorf("stdout is empty")
	}
	for i, b := range output {
		if b != '{' && b != '[' {
			continue
		}
		var raw json.RawMessage
		decoder := json.NewDecoder(bytes.NewReader(output[i:]))
		if err := decoder.Decode(&raw); err == nil {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("no valid JSON found in stdout")
}

func snykHighCritical(findings []snykVulnerability) []snykVulnerability {
	var targets []snykVulnerability
	for _, finding := range findings {
		switch strings.ToUpper(finding.Severity) {
		case "HIGH", "CRITICAL":
			targets = append(targets, finding)
		}
	}
	return targets
}

func groupSnykFindings(findings []snykVulnerability) []snykRemediationGroup {
	seen := make(map[string]int)
	var groups []snykRemediationGroup

	for _, finding := range findings {
		manifest := snykManifestPath(finding)
		packageName := finding.PackageName
		if packageName == "" {
			packageName = finding.Name
		}
		key := manifest + "\x00" + packageName
		if idx, ok := seen[key]; ok {
			groups[idx].Findings = append(groups[idx].Findings, finding)
			continue
		}
		seen[key] = len(groups)
		groups = append(groups, snykRemediationGroup{
			ManifestFile: manifest,
			PackageName:  packageName,
			Findings:     []snykVulnerability{finding},
		})
	}

	sort.SliceStable(groups, func(i, j int) bool {
		return snykGroupPriority(groups[i]) < snykGroupPriority(groups[j])
	})
	return groups
}

func snykGroupFindingIDs(group snykRemediationGroup) []string {
	ids := make([]string, 0, len(group.Findings))
	for _, finding := range group.Findings {
		if finding.ID != "" {
			ids = append(ids, finding.ID)
		}
	}
	sort.Strings(ids)
	return ids
}
func snykGroupPriority(group snykRemediationGroup) int {
	switch {
	case strings.HasPrefix(group.PackageName, "org.springframework.boot:"):
		return 0
	case strings.HasPrefix(group.PackageName, "org.springframework:"):
		return 2
	default:
		return 1
	}
}

func snykTargetFile(result snykScanResult) string {
	for _, candidate := range []string{result.TargetFile, result.DisplayTargetFile} {
		if candidate != "" {
			return filepath.ToSlash(candidate)
		}
	}
	switch result.PackageManager {
	case "maven":
		return "pom.xml"
	case "npm", "yarn":
		return "package.json"
	default:
		return ""
	}
}

func snykManifestPath(finding snykVulnerability) string {
	if finding.ManifestFile != "" {
		return finding.ManifestFile
	}
	target := finding.TargetFile
	if target == "" {
		switch finding.PackageManager {
		case "maven":
			target = "pom.xml"
		case "npm", "yarn":
			target = "package.json"
		}
	}
	if finding.ProjectPath == "" || finding.ProjectPath == "." {
		return target
	}
	return filepath.ToSlash(filepath.Join(finding.ProjectPath, target))
}

func snykManifestFile(root string, result snykScanResult) string {
	target := snykTargetFile(result)
	if target == "" {
		return ""
	}

	candidate := filepath.FromSlash(target)
	if !filepath.IsAbs(candidate) && result.Path != "" && result.Path != "." {
		candidate = filepath.Join(filepath.FromSlash(result.Path), candidate)
	}

	rel, err := filepath.Rel(root, candidate)
	if err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return filepath.ToSlash(rel)
	}

	return filepath.ToSlash(filepath.Clean(candidate))
}

func snykManifestContext(root string, finding snykVulnerability) (string, error) {
	manifest := snykManifestPath(finding)
	path, err := safeJoin(root, manifest)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read manifest %s: %w", manifest, err)
	}
	return fmt.Sprintf("--- %s ---\n%s", manifest, string(data)), nil
}

func buildSnykRemediationPrompt(projectInfo *detectors.ProjectInfo, finding snykVulnerability, contextText string) string {
	return fmt.Sprintf(`You are an expert dependency remediation agent.

Project:
- Language: %s
- Framework: %s
- Detected package file: %s

Snyk vulnerability:
- ID: %s
- Title: %s
- Severity: %s
- Package: %s
- Current version: %s
- Package manager: %s
- Project: %s
- Manifest: %s
- Is upgradable: %t
- Is patchable: %t
- Nearest fixed version: %s
- Fixed in versions: %s
- Upgrade path: %s
- Dependency paths: %s
- Recommendation: %s
- Description: %s

Manifest / lockfile context:
%s

Strict instructions:
- Apply exactly the Snyk remediation recommendation.
- Fix only this vulnerability.
- Prefer manifest and lockfile changes when appropriate.
- Do not modify unrelated business logic.
- Keep Spring Boot / React compatibility.
- Return only a unified diff patch that can be applied with git apply.
- Do not include markdown fences, explanations, prose, or comments outside the patch.
- The patch must include file headers (diff --git or ---/+++).
`, projectInfo.Language, projectInfo.Framework, projectInfo.PackageFile, finding.ID, finding.Title, strings.ToUpper(finding.Severity), finding.PackageName, finding.Version, finding.PackageManager, finding.ProjectName, snykManifestPath(finding), finding.IsUpgradable, finding.IsPatchable, finding.NearestFixedInVersion, strings.Join(finding.FixedIn, ", "), formatUpgradePath(finding.UpgradePath), strings.Join(finding.From, " > "), finding.Recommendation, finding.Description, contextText)
}

func buildSnykGroupRemediationPrompt(projectInfo *detectors.ProjectInfo, group snykRemediationGroup, contextText string) string {
	finding := group.Findings[0]
	return fmt.Sprintf(`You are an expert dependency remediation agent.

Project:
- Language: %s
- Framework: %s
- Detected package file: %s

Snyk vulnerable dependency group:
- Package: %s
- Current version: %s
- Package manager: %s
- Project: %s
- Manifest: %s
- Findings in this group: %d

Snyk findings to fix together:
%s

Manifest / lockfile context:
%s

Strict instructions:
- Apply the Snyk remediation recommendation for this dependency.
- Fix all listed HIGH/CRITICAL vulnerabilities for this package in one patch.
- Prefer the lowest safe fixed version that resolves all listed findings.
- Prefer manifest and lockfile changes when appropriate.
- Do not modify unrelated business logic.
- Keep Spring Boot / React compatibility.
- Return only a unified diff patch that can be applied with git apply.
- Do not include markdown fences, explanations, prose, or comments outside the patch.
- The patch must include file headers (diff --git or ---/+++).
`, projectInfo.Language, projectInfo.Framework, projectInfo.PackageFile, group.PackageName, finding.Version, finding.PackageManager, finding.ProjectName, group.ManifestFile, len(group.Findings), snykGroupFindingsText(group), contextText)
}

func snykGroupFindingsText(group snykRemediationGroup) string {
	var b strings.Builder
	for _, finding := range group.Findings {
		fmt.Fprintf(&b, "- ID: %s\n", finding.ID)
		fmt.Fprintf(&b, "  Title: %s\n", finding.Title)
		fmt.Fprintf(&b, "  Severity: %s\n", strings.ToUpper(finding.Severity))
		fmt.Fprintf(&b, "  Nearest fixed version: %s\n", finding.NearestFixedInVersion)
		fmt.Fprintf(&b, "  Fixed in versions: %s\n", strings.Join(finding.FixedIn, ", "))
		fmt.Fprintf(&b, "  Upgrade path: %s\n", formatUpgradePath(finding.UpgradePath))
		fmt.Fprintf(&b, "  Recommendation: %s\n", finding.Recommendation)
	}
	return b.String()
}

func formatUpgradePath(path []interface{}) string {
	if len(path) == 0 {
		return ""
	}
	parts := make([]string, 0, len(path))
	for _, item := range path {
		switch v := item.(type) {
		case string:
			parts = append(parts, v)
		case bool:
			parts = append(parts, fmt.Sprintf("%t", v))
		default:
			parts = append(parts, fmt.Sprintf("%v", v))
		}
	}
	return strings.Join(parts, " > ")
}

func snykFindingStillPresent(original snykVulnerability, findings []snykVulnerability) bool {
	for _, finding := range findings {
		if finding.ID == original.ID && finding.PackageName == original.PackageName {
			return true
		}
	}
	return false
}

func snykGroupStillPresent(group snykRemediationGroup, findings []snykVulnerability) bool {
	return snykGroupPresentCount(group, findings) > 0
}

func snykGroupPresentCount(group snykRemediationGroup, findings []snykVulnerability) int {
	count := 0
	for _, original := range group.Findings {
		if snykFindingStillPresent(original, findings) {
			count++
		}
	}
	return count
}

func applySnykDependencyFallback(root string, group snykRemediationGroup) ([]fileBackup, error) {
	switch {
	case strings.HasSuffix(group.ManifestFile, "pom.xml"):
		return applySnykMavenFallback(root, group)
	case strings.HasSuffix(group.ManifestFile, "build.gradle") || strings.HasSuffix(group.ManifestFile, "build.gradle.kts"):
		return applySnykGradleFallback(root, group)
	default:
		return nil, fmt.Errorf("no deterministic fallback for manifest %s", group.ManifestFile)
	}
}

func applySnykMavenFallback(root string, group snykRemediationGroup) ([]fileBackup, error) {
	groupID, artifactID, ok := strings.Cut(group.PackageName, ":")
	if !ok || groupID == "" || artifactID == "" {
		return nil, fmt.Errorf("package %s is not a Maven coordinate", group.PackageName)
	}
	version := snykGroupFixedVersion(group)
	if version == "" {
		return nil, fmt.Errorf("no fixed version found for %s", group.PackageName)
	}

	path, err := safeJoin(root, group.ManifestFile)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	updated, changed := updateDirectMavenDependencyVersion(string(data), groupID, artifactID, version)
	if !changed && strings.HasPrefix(group.PackageName, "org.springframework.boot:") {
		updated, changed = updateSpringBootParentVersion(string(data), version)
	}
	if !changed {
		return nil, fmt.Errorf("dependency %s was not found as a direct dependency in %s", group.PackageName, group.ManifestFile)
	}

	backups := []fileBackup{{Path: path, Data: data, Exists: true}}
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		return nil, err
	}
	return backups, nil
}

func applySnykGradleFallback(root string, group snykRemediationGroup) ([]fileBackup, error) {
	groupID, artifactID, ok := strings.Cut(group.PackageName, ":")
	if !ok || groupID == "" || artifactID == "" {
		return nil, fmt.Errorf("package %s is not a Maven coordinate", group.PackageName)
	}
	version := snykGroupFixedVersion(group)
	if version == "" {
		return nil, fmt.Errorf("no fixed version found for %s", group.PackageName)
	}

	path, err := safeJoin(root, group.ManifestFile)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	updated, changed := updateDirectGradleDependencyVersion(string(data), groupID, artifactID, version)
	if !changed {
		return nil, fmt.Errorf("dependency %s was not found as a direct dependency in %s", group.PackageName, group.ManifestFile)
	}

	backups := []fileBackup{{Path: path, Data: data, Exists: true}}
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		return nil, err
	}
	return backups, nil
}
func snykGroupFixedVersion(group snykRemediationGroup) string {
	var nearest []string
	var fixed []string
	var recommended []string
	for _, finding := range group.Findings {
		if finding.NearestFixedInVersion != "" {
			nearest = append(nearest, finding.NearestFixedInVersion)
		}
		fixed = append(fixed, finding.FixedIn...)
		recommended = append(recommended, versionsFromText(finding.Recommendation)...)
	}
	if version := highestVersion(nearest); version != "" {
		return version
	}
	if version := highestVersion(fixed); version != "" {
		return version
	}
	return highestVersion(recommended)
}

func versionsFromText(text string) []string {
	re := regexp.MustCompile(`\b\d+(?:\.\d+){1,4}(?:[-.][A-Za-z0-9]+)?\b`)
	return re.FindAllString(text, -1)
}

func highestVersion(versions []string) string {
	best := ""
	for _, version := range versions {
		version = strings.TrimSpace(version)
		if version == "" {
			continue
		}
		if best == "" || compareMavenVersion(version, best) > 0 {
			best = version
		}
	}
	return best
}

func compareMavenVersion(a, b string) int {
	aParts := versionParts(a)
	bParts := versionParts(b)
	max := len(aParts)
	if len(bParts) > max {
		max = len(bParts)
	}
	for i := 0; i < max; i++ {
		ai, bi := 0, 0
		if i < len(aParts) {
			ai = aParts[i]
		}
		if i < len(bParts) {
			bi = bParts[i]
		}
		if ai > bi {
			return 1
		}
		if ai < bi {
			return -1
		}
	}
	return 0
}

func versionParts(version string) []int {
	re := regexp.MustCompile(`\d+`)
	matches := re.FindAllString(version, -1)
	parts := make([]int, 0, len(matches))
	for _, match := range matches {
		var value int
		for _, ch := range match {
			value = value*10 + int(ch-'0')
		}
		parts = append(parts, value)
	}
	return parts
}

func updateDirectGradleDependencyVersion(buildFile, groupID, artifactID, version string) (string, bool) {
	dependency := regexp.QuoteMeta(groupID + ":" + artifactID)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)((?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)\s+['"]` + dependency + `:)[^'"]+(['"])`),
		regexp.MustCompile(`(?m)((?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)\(["']` + dependency + `:)[^'"]+(["']\))`),
	}
	for _, pattern := range patterns {
		if pattern.MatchString(buildFile) {
			return pattern.ReplaceAllString(buildFile, `${1}`+version+`${2}`), true
		}
	}
	return buildFile, false
}
func updateDirectMavenDependencyVersion(pom, groupID, artifactID, version string) (string, bool) {
	dependencyRe := regexp.MustCompile(`(?s)<dependency>.*?</dependency>`)
	locs := dependencyRe.FindAllStringIndex(pom, -1)
	for _, loc := range locs {
		block := pom[loc[0]:loc[1]]
		if !mavenTagEquals(block, "groupId", groupID) || !mavenTagEquals(block, "artifactId", artifactID) {
			continue
		}
		versionRe := regexp.MustCompile(`(?s)(<version>\s*)[^<]+(\s*</version>)`)
		if !versionRe.MatchString(block) {
			return "", false
		}
		newBlock := versionRe.ReplaceAllString(block, "${1}"+version+"${2}")
		return pom[:loc[0]] + newBlock + pom[loc[1]:], newBlock != block
	}
	return "", false
}

func updateSpringBootParentVersion(pom, version string) (string, bool) {
	parentRe := regexp.MustCompile(`(?s)<parent>.*?</parent>`)
	loc := parentRe.FindStringIndex(pom)
	if loc == nil {
		return "", false
	}
	block := pom[loc[0]:loc[1]]
	if !mavenTagEquals(block, "groupId", "org.springframework.boot") ||
		!mavenTagEquals(block, "artifactId", "spring-boot-starter-parent") {
		return "", false
	}
	versionRe := regexp.MustCompile(`(?s)(<version>\s*)[^<]+(\s*</version>)`)
	if !versionRe.MatchString(block) {
		return "", false
	}
	newBlock := versionRe.ReplaceAllString(block, "${1}"+version+"${2}")
	return pom[:loc[0]] + newBlock + pom[loc[1]:], newBlock != block
}

func mavenTagEquals(block, tag, value string) bool {
	re := regexp.MustCompile(`(?s)<` + regexp.QuoteMeta(tag) + `>\s*` + regexp.QuoteMeta(value) + `\s*</` + regexp.QuoteMeta(tag) + `>`)
	return re.MatchString(block)
}

func runValidationForFiles(root string, projectInfo *detectors.ProjectInfo, files []string) error {
	commands := validationCommandsForFiles(root, projectInfo, files)
	if len(commands) == 0 {
		return runProjectTests(root, projectInfo)
	}

	for _, command := range commands {
		cmd := exec.Command(command.Name, command.Args...)
		cmd.Dir = command.Dir
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s %s failed: %w\n%s", command.Name, strings.Join(command.Args, " "), err, commandOutputTail(output, 40))
		}
	}
	return nil
}

type validationCommand struct {
	Dir  string
	Name string
	Args []string
}

func validationCommandsForFiles(root string, projectInfo *detectors.ProjectInfo, files []string) []validationCommand {
	seen := make(map[string]bool)
	var commands []validationCommand

	for _, file := range files {
		clean := filepath.ToSlash(filepath.Clean(file))
		switch {
		case strings.HasSuffix(clean, "pom.xml"):
			dir := filepath.Dir(filepath.Join(root, clean))
			key := "maven:" + dir
			if !seen[key] {
				seen[key] = true
				name, args := mavenCommand(dir)
				commands = append(commands, validationCommand{Dir: dir, Name: name, Args: args})
			}
		case strings.HasSuffix(clean, "build.gradle") || strings.HasSuffix(clean, "build.gradle.kts"):
			dir := filepath.Dir(filepath.Join(root, clean))
			key := "gradle:" + dir
			if !seen[key] {
				seen[key] = true
				name, args := gradleCommand(dir)
				commands = append(commands, validationCommand{Dir: dir, Name: name, Args: args})
			}
		case strings.HasSuffix(clean, "package.json"):
			dir := filepath.Dir(filepath.Join(root, clean))
			key := "npm:" + dir
			if !seen[key] {
				seen[key] = true
				commands = append(commands, validationCommand{Dir: dir, Name: "npm", Args: []string{"test"}})
			}
		}
	}

	if len(commands) == 0 && projectInfo != nil {
		name, args, err := testCommand(root, projectInfo)
		if err == nil {
			commands = append(commands, validationCommand{Dir: root, Name: name, Args: args})
		}
	}

	sort.Slice(commands, func(i, j int) bool {
		if commands[i].Dir != commands[j].Dir {
			return commands[i].Dir < commands[j].Dir
		}
		return commands[i].Name < commands[j].Name
	})
	return commands
}

func mavenCommand(dir string) (string, []string) {
	if runtime.GOOS == "windows" && fileExists(filepath.Join(dir, "mvnw.cmd")) {
		return filepath.Join(dir, "mvnw.cmd"), []string{"test"}
	}
	if fileExists(filepath.Join(dir, "mvnw")) {
		return filepath.Join(dir, "mvnw"), []string{"test"}
	}
	return "mvn", []string{"test"}
}

func gradleCommand(dir string) (string, []string) {
	if runtime.GOOS == "windows" && fileExists(filepath.Join(dir, "gradlew.bat")) {
		return filepath.Join(dir, "gradlew.bat"), []string{"test"}
	}
	if fileExists(filepath.Join(dir, "gradlew")) {
		return filepath.Join(dir, "gradlew"), []string{"test"}
	}
	return "gradle", []string{"test"}
}
