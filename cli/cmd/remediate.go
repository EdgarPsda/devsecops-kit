package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/edgarpsda/devsecops-kit/cli/ai"
	"github.com/edgarpsda/devsecops-kit/cli/config"
	"github.com/edgarpsda/devsecops-kit/cli/detectors"
	"github.com/edgarpsda/devsecops-kit/cli/scanners"
	"github.com/edgarpsda/devsecops-kit/internal/remediation"
)

var (
	remediatePlan       bool
	remediateConfigPath string
	remediateProvider   string
)

var remediateCmd = &cobra.Command{
	Use:   "remediate",
	Short: "Run or plan security remediation workflow",
	Long: `Run the Security Auto Remediation workflow.

By default this command runs a vertical-slice MVP:
- Snyk Open Source scan
- AI patch generation for HIGH/CRITICAL findings
- apply patch on a new Git branch
- project test command
- Snyk re-scan

It does not commit, push, or open pull requests.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRemediate()
	},
}

func init() {
	rootCmd.AddCommand(remediateCmd)

	remediateCmd.Flags().BoolVar(&remediatePlan, "plan", false, "Show the remediation dry run plan")
	remediateCmd.Flags().StringVar(&remediateConfigPath, "config", "security-config.yml", "Path to security-config.yml")
	remediateCmd.Flags().StringVar(&remediateProvider, "provider", "snyk", "Remediation provider: snyk, semgrep")
}

func runRemediate() error {
	dir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	secConfig, err := config.LoadConfig(filepath.Join(dir, remediateConfigPath))
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	if !remediatePlan {
		switch strings.ToLower(remediateProvider) {
		case "snyk":
			return runSnykRemediationMVP(dir, secConfig)
		case "semgrep":
			return runRemediationMVP(dir, secConfig)
		default:
			return fmt.Errorf("unsupported remediation provider: %s", remediateProvider)
		}
	}

	engine := remediation.NewEngineWithValidation(
		remediation.Options{DryRun: true},
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
	)

	printRemediationPlan(dir, secConfig, engine)
	return nil
}

type remediationAttempt struct {
	Finding       scanners.Finding
	Status        string
	Reason        string
	ModifiedFiles []string
}

type fileBackup struct {
	Path   string
	Data   []byte
	Exists bool
}

func runRemediationMVP(dir string, secConfig *config.SecurityConfig) error {
	projectInfo, err := detectors.DetectProject(dir)
	if err != nil {
		return fmt.Errorf("failed to detect project: %w", err)
	}

	if !secConfig.AI.Enabled {
		return fmt.Errorf("AI remediation requires ai.enabled=true in %s", remediateConfigPath)
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

	fmt.Println("🔍 Running Semgrep scan...")
	report, err := runSemgrepOnly(dir, secConfig)
	if err != nil {
		return err
	}

	targets := highCriticalFindings(report.AllFindings)
	if len(targets) == 0 {
		fmt.Println("✅ No HIGH or CRITICAL Semgrep findings found. Nothing to remediate.")
		return nil
	}

	originalBranch, err := gitOutput(dir, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return fmt.Errorf("failed to detect current git branch: %w", err)
	}

	if dirty, err := gitHasChanges(dir); err != nil {
		return err
	} else if dirty {
		return fmt.Errorf("working tree has existing changes; commit, stash, or clean them before auto remediation")
	}

	fmt.Println("🧪 Running baseline project validation...")
	if err := runProjectTests(dir, projectInfo); err != nil {
		return fmt.Errorf("baseline validation failed; fix the project tests before auto remediation:\n%w", err)
	}

	branchName := "security/remediation-" + time.Now().Format("20060102-150405")
	if _, err := gitOutput(dir, "checkout", "-b", branchName); err != nil {
		return fmt.Errorf("failed to create remediation branch: %w", err)
	}

	summary := struct {
		Scanned       int
		Fixed         int
		Failed        int
		ModifiedFiles map[string]bool
		Attempts      []remediationAttempt
		Remaining     int
		Branch        string
	}{
		Scanned:       len(report.AllFindings),
		ModifiedFiles: make(map[string]bool),
		Branch:        branchName,
	}

	for _, finding := range targets {
		fmt.Printf("\n🛠 Remediating %s (%s) in %s:%d\n", finding.RuleID, finding.Severity, finding.File, finding.Line)

		contextText, err := codeContext(dir, finding.File, finding.Line, 20)
		if err != nil {
			summary.Failed++
			summary.Attempts = append(summary.Attempts, remediationAttempt{Finding: finding, Status: "FAILED", Reason: err.Error()})
			fmt.Printf("❌ Failed to read context: %v\n", err)
			continue
		}

		prompt := buildRemediationPrompt(projectInfo, finding, contextText)
		response, err := aiClient.Complete(prompt)
		if err != nil {
			summary.Failed++
			summary.Attempts = append(summary.Attempts, remediationAttempt{Finding: finding, Status: "FAILED", Reason: err.Error()})
			fmt.Printf("❌ AI provider failed: %v\n", err)
			continue
		}

		backups, err := applyAIPatchWithRepair(dir, aiClient, prompt, response)
		if err != nil {
			summary.Failed++
			summary.Attempts = append(summary.Attempts, remediationAttempt{Finding: finding, Status: "FAILED", Reason: err.Error()})
			fmt.Printf("❌ Failed to apply patch: %v\n", err)
			continue
		}

		modifiedFiles, err := gitChangedFiles(dir)
		if err != nil {
			_ = restoreBackups(backups)
			summary.Failed++
			summary.Attempts = append(summary.Attempts, remediationAttempt{Finding: finding, Status: "FAILED", Reason: err.Error()})
			fmt.Printf("❌ Failed to detect modified files: %v\n", err)
			continue
		}

		fmt.Println("🧪 Running project validation...")
		if err := runProjectTests(dir, projectInfo); err != nil {
			_ = restoreBackups(backups)
			summary.Failed++
			summary.Attempts = append(summary.Attempts, remediationAttempt{Finding: finding, Status: "FAILED", Reason: "build/tests failed: " + err.Error(), ModifiedFiles: modifiedFiles})
			fmt.Printf("❌ Build/tests failed. Changes restored: %v\n", err)
			continue
		}

		fmt.Println("🔁 Re-running Semgrep...")
		rescan, err := runSemgrepOnly(dir, secConfig)
		if err != nil {
			_ = restoreBackups(backups)
			summary.Failed++
			summary.Attempts = append(summary.Attempts, remediationAttempt{Finding: finding, Status: "FAILED", Reason: "rescan failed: " + err.Error(), ModifiedFiles: modifiedFiles})
			fmt.Printf("❌ Semgrep re-scan failed. Changes restored: %v\n", err)
			continue
		}

		if findingStillPresent(finding, rescan.AllFindings) {
			_ = restoreBackups(backups)
			summary.Failed++
			summary.Attempts = append(summary.Attempts, remediationAttempt{Finding: finding, Status: "FAILED", Reason: "finding still present after remediation", ModifiedFiles: modifiedFiles})
			fmt.Println("❌ Finding still present. Changes restored.")
			continue
		}

		summary.Fixed++
		for _, file := range modifiedFiles {
			summary.ModifiedFiles[file] = true
		}
		summary.Attempts = append(summary.Attempts, remediationAttempt{Finding: finding, Status: "FIXED", ModifiedFiles: modifiedFiles})
		fmt.Println("✅ Finding fixed.")
	}

	finalReport, err := runSemgrepOnly(dir, secConfig)
	if err == nil {
		summary.Remaining = len(finalReport.AllFindings)
	}

	if summary.Fixed == 0 {
		_, _ = gitOutput(dir, "checkout", originalBranch)
		_, _ = gitOutput(dir, "branch", "-D", branchName)
		summary.Branch = "(deleted - no successful fixes)"
	}

	printRemediationSummary(summary.Scanned, summary.Fixed, summary.Failed, sortedMapKeys(summary.ModifiedFiles), summary.Remaining, summary.Branch)
	return nil
}

func printRemediationPlan(projectDir string, secConfig *config.SecurityConfig, engine *remediation.Engine) {
	fmt.Println("🛠 Security Auto Remediation Plan")
	fmt.Println("--------------------------------")
	fmt.Printf("Project root: %s\n", projectDir)
	fmt.Printf("Mode: dry run (no files, branches, commits, pushes, or pull requests will be created)\n")
	fmt.Printf("Engine dry run: %t\n\n", engine.Options().DryRun)

	fmt.Println("1. Findings encontrados")
	fmt.Println("   - 0 findings loaded in this phase")
	fmt.Println("   - Dry run does not execute scanners yet")
	fmt.Println("   - Future finding providers: Semgrep, Trivy, Gitleaks, Checkov, Snyk, SARIF")
	fmt.Println()

	fmt.Println("2. Recomendaciones disponibles")
	fmt.Println("   - 0 recommendations loaded in this phase")
	fmt.Println("   - Future recommendation providers: Snyk, GitHub Security Advisories, OSV, NVD")
	fmt.Println("   - AI patch generation is not enabled in this phase")
	fmt.Println()

	fmt.Println("3. Archivos potencialmente modificados")
	fmt.Println("   - No files are inspected or modified by --plan")
	fmt.Println("   - Future patches will target files referenced by normalized findings and recommendations")
	fmt.Println()

	fmt.Println("4. Validaciones que se ejecutarían")
	for _, check := range remediationPlanValidations() {
		fmt.Printf("   - %s\n", check)
	}
	fmt.Println()

	fmt.Println("5. Scanners que volverían a correr")
	for _, scanner := range remediationPlanScanners(secConfig) {
		fmt.Printf("   - %s\n", scanner)
	}
	fmt.Println()

	fmt.Println("6. Git")
	fmt.Println("   - Branch creation: skipped in --plan")
	fmt.Println("   - Diff generation: planned for future phases")
	fmt.Println("   - Rollback/restore: planned for future phases")
}

func remediationPlanValidations() []string {
	return []string{
		"Build",
		"Unit Tests",
		"Integration Tests",
		"Security Re-scan",
	}
}

func remediationPlanScanners(secConfig *config.SecurityConfig) []string {
	var scanners []string
	if secConfig.Tools.Semgrep {
		scanners = append(scanners, "Semgrep")
	}
	if secConfig.Tools.Trivy {
		scanners = append(scanners, "Trivy")
	}
	if secConfig.Tools.Gitleaks {
		scanners = append(scanners, "Gitleaks")
	}
	if secConfig.Tools.Checkov {
		scanners = append(scanners, "Checkov")
	}
	if secConfig.Licenses.Enabled {
		scanners = append(scanners, "License scan")
	}
	if len(scanners) == 0 {
		scanners = append(scanners, "None configured")
	}
	return scanners
}

func runSemgrepOnly(dir string, secConfig *config.SecurityConfig) (*scanners.ScanReport, error) {
	options := scanners.ScanOptions{
		EnableSemgrep:    true,
		EnableGitleaks:   false,
		EnableTrivy:      false,
		EnableCheckov:    false,
		EnableLicenses:   false,
		ExcludePaths:     secConfig.ExcludePaths,
		FailOnThresholds: secConfig.FailOn,
		Verbose:          false,
	}

	orchestrator := scanners.NewOrchestrator(dir, options)
	report, err := orchestrator.Run()
	if err != nil {
		return nil, fmt.Errorf("semgrep scan failed: %w", err)
	}
	return report, nil
}

func highCriticalFindings(findings []scanners.Finding) []scanners.Finding {
	var targets []scanners.Finding
	for _, finding := range findings {
		if finding.Tool != "semgrep" {
			continue
		}
		if finding.Severity == "HIGH" || finding.Severity == "CRITICAL" {
			targets = append(targets, finding)
		}
	}
	return targets
}

func aiAPIKey(secConfig *config.SecurityConfig) string {
	if secConfig.AI.APIKey != "" {
		return secConfig.AI.APIKey
	}
	switch secConfig.AI.Provider {
	case "openai":
		return os.Getenv("OPENAI_API_KEY")
	case "anthropic":
		return os.Getenv("ANTHROPIC_API_KEY")
	default:
		return ""
	}
}

func buildRemediationPrompt(projectInfo *detectors.ProjectInfo, finding scanners.Finding, contextText string) string {
	return fmt.Sprintf(`You are an expert secure code remediation agent.

Project:
- Language: %s
- Framework: %s
- Package file: %s

Security finding:
- Tool: %s
- Severity: %s
- Rule: %s
- File: %s
- Line: %d
- Message: %s

Affected code and nearby context:
%s

Strict instructions:
- Fix only this vulnerability.
- Do not modify unrelated business logic.
- Preserve existing behavior and compatibility.
- Make the smallest safe change.
- Return only a unified diff patch that can be applied with git apply.
- Do not include markdown fences, explanations, prose, or comments outside the patch.
- The patch must include file headers (diff --git or ---/+++).
`, projectInfo.Language, projectInfo.Framework, projectInfo.PackageFile, finding.Tool, finding.Severity, finding.RuleID, finding.File, finding.Line, finding.Message, contextText)
}

func codeContext(root, relPath string, line, radius int) (string, error) {
	path, err := safeJoin(root, relPath)
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", relPath, err)
	}

	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	if line <= 0 {
		line = 1
	}

	start := line - radius
	if start < 1 {
		start = 1
	}
	end := line + radius
	if end > len(lines) {
		end = len(lines)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "--- %s:%d-%d ---\n", relPath, start, end)
	for i := start; i <= end; i++ {
		fmt.Fprintf(&b, "%4d | %s\n", i, lines[i-1])
	}
	return b.String(), nil
}

func safeJoin(root, relPath string) (string, error) {
	if relPath == "" {
		return "", fmt.Errorf("empty file path")
	}
	if filepath.IsAbs(relPath) {
		return "", fmt.Errorf("absolute paths are not allowed: %s", relPath)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	absPath, err := filepath.Abs(filepath.Join(absRoot, filepath.Clean(relPath)))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes project root: %s", relPath)
	}
	return absPath, nil
}

func extractUnifiedDiff(response string) (string, error) {
	text := strings.TrimSpace(response)
	if strings.Contains(text, "```") {
		parts := strings.Split(text, "```")
		for _, part := range parts {
			part = strings.TrimSpace(strings.TrimPrefix(part, "diff"))
			if strings.Contains(part, "diff --git ") || strings.HasPrefix(part, "--- ") {
				text = strings.TrimSpace(part)
				break
			}
		}
	}

	if idx := strings.Index(text, "diff --git "); idx >= 0 {
		return strings.TrimSpace(text[idx:]) + "\n", nil
	}
	if idx := strings.Index(text, "--- "); idx >= 0 {
		return strings.TrimSpace(text[idx:]) + "\n", nil
	}

	return "", fmt.Errorf("no unified diff found")
}

func diffFiles(patch string) []string {
	seen := make(map[string]bool)
	for _, line := range strings.Split(patch, "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				file := strings.TrimPrefix(fields[3], "b/")
				seen[file] = true
			}
			continue
		}
		if strings.HasPrefix(line, "+++ b/") {
			seen[strings.TrimPrefix(strings.TrimSpace(line), "+++ b/")] = true
		}
	}
	return sortedMapKeys(seen)
}

func backupFiles(root string, files []string) ([]fileBackup, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("patch did not identify modified files")
	}

	backups := make([]fileBackup, 0, len(files))
	for _, file := range files {
		path, err := safeJoin(root, file)
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				backups = append(backups, fileBackup{Path: path, Exists: false})
				continue
			}
			return nil, err
		}
		backups = append(backups, fileBackup{Path: path, Data: data, Exists: true})
	}
	return backups, nil
}

func restoreBackups(backups []fileBackup) error {
	for _, backup := range backups {
		if !backup.Exists {
			if err := os.Remove(backup.Path); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		if err := os.WriteFile(backup.Path, backup.Data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func gitApply(dir, patch string) error {
	cmd := exec.Command("git", "apply", "--whitespace=nowarn")
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(patch)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func applyAIPatchWithRepair(dir string, aiClient *ai.Client, prompt, response string) ([]fileBackup, error) {
	patch, err := extractUnifiedDiff(response)
	if err != nil {
		repaired, repairErr := repairAIPatch(aiClient, prompt, response, "", err)
		if repairErr != nil {
			return nil, fmt.Errorf("AI response did not contain a usable patch: %w", err)
		}
		patch = repaired
	}

	backups, err := backupFiles(dir, diffFiles(patch))
	if err != nil {
		repaired, repairErr := repairAIPatch(aiClient, prompt, response, patch, err)
		if repairErr != nil {
			return nil, err
		}
		patch = repaired
		backups, err = backupFiles(dir, diffFiles(patch))
		if err != nil {
			return nil, err
		}
	}

	if err := gitApply(dir, patch); err != nil {
		_ = restoreBackups(backups)
		repaired, repairErr := repairAIPatch(aiClient, prompt, response, patch, err)
		if repairErr != nil {
			return nil, err
		}
		patch = repaired
		backups, err = backupFiles(dir, diffFiles(patch))
		if err != nil {
			return nil, err
		}
		if err := gitApply(dir, patch); err != nil {
			_ = restoreBackups(backups)
			return nil, err
		}
	}

	return backups, nil
}

func repairAIPatch(aiClient *ai.Client, originalPrompt, response, patch string, applyErr error) (string, error) {
	var b strings.Builder
	b.WriteString(originalPrompt)
	b.WriteString("\n\nThe previous response could not be applied as a patch.\n")
	b.WriteString("Return only a corrected unified diff patch. Do not change the intended security fix.\n")
	b.WriteString("The patch must be accepted by: git apply --whitespace=nowarn\n")
	b.WriteString("Git/extraction error:\n")
	b.WriteString(applyErr.Error())
	b.WriteString("\n\nPrevious AI response:\n")
	b.WriteString(response)
	if patch != "" && patch != response {
		b.WriteString("\n\nExtracted patch:\n")
		b.WriteString(patch)
	}

	repaired, err := aiClient.Complete(b.String())
	if err != nil {
		return "", err
	}
	return extractUnifiedDiff(repaired)
}

func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func gitHasChanges(dir string) (bool, error) {
	output, err := gitOutput(dir, "status", "--porcelain")
	if err != nil {
		return false, fmt.Errorf("failed to inspect git status: %w", err)
	}
	return strings.TrimSpace(output) != "", nil
}

func gitChangedFiles(dir string) ([]string, error) {
	output, err := gitOutput(dir, "diff", "--name-only")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			files = append(files, line)
		}
	}
	sort.Strings(files)
	return files, nil
}

func runProjectTests(dir string, projectInfo *detectors.ProjectInfo) error {
	name, args, err := testCommand(dir, projectInfo)
	if err != nil {
		return err
	}

	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, commandOutputTail(output, 40))
	}
	return nil
}

func commandOutputTail(output []byte, maxLines int) string {
	text := strings.TrimSpace(string(output))
	if text == "" {
		return ""
	}
	lines := strings.Split(text, "\n")
	if len(lines) <= maxLines {
		return text
	}
	return strings.TrimSpace(strings.Join(lines[len(lines)-maxLines:], "\n"))
}

func testCommand(dir string, projectInfo *detectors.ProjectInfo) (string, []string, error) {
	switch projectInfo.Language {
	case "java":
		if strings.HasPrefix(projectInfo.PackageFile, "build.gradle") {
			if runtime.GOOS == "windows" && fileExists(filepath.Join(dir, "gradlew.bat")) {
				return filepath.Join(dir, "gradlew.bat"), []string{"test"}, nil
			}
			if fileExists(filepath.Join(dir, "gradlew")) {
				return filepath.Join(dir, "gradlew"), []string{"test"}, nil
			}
			return "gradle", []string{"test"}, nil
		}
		if runtime.GOOS == "windows" && fileExists(filepath.Join(dir, "mvnw.cmd")) {
			return filepath.Join(dir, "mvnw.cmd"), []string{"test"}, nil
		}
		if fileExists(filepath.Join(dir, "mvnw")) {
			return filepath.Join(dir, "mvnw"), []string{"test"}, nil
		}
		return "mvn", []string{"test"}, nil
	case "nodejs":
		return "npm", []string{"test"}, nil
	case "python":
		return "pytest", nil, nil
	case "golang":
		return "go", []string{"test", "./..."}, nil
	default:
		return "", nil, fmt.Errorf("no validation command for language %s", projectInfo.Language)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func findingStillPresent(original scanners.Finding, findings []scanners.Finding) bool {
	for _, finding := range findings {
		if finding.Tool != original.Tool {
			continue
		}
		if finding.RuleID == original.RuleID && filepath.Clean(finding.File) == filepath.Clean(original.File) {
			return true
		}
	}
	return false
}

func sortedMapKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func printRemediationSummary(scanned, fixed, failed int, modifiedFiles []string, remaining int, branch string) {
	fmt.Println()
	fmt.Println("--------------------------------------------------")
	fmt.Println("Auto Remediation Summary")
	fmt.Println()
	fmt.Println("Scanned:")
	fmt.Printf("%d findings\n\n", scanned)
	fmt.Println("Fixed:")
	fmt.Printf("%d\n\n", fixed)
	fmt.Println("Failed:")
	fmt.Printf("%d\n\n", failed)
	fmt.Println("Modified files:")
	if len(modifiedFiles) == 0 {
		fmt.Println("(none)")
	} else {
		for _, file := range modifiedFiles {
			fmt.Println(file)
		}
	}
	fmt.Println()
	fmt.Println("Remaining findings:")
	fmt.Printf("%d\n\n", remaining)
	fmt.Println("Branch:")
	fmt.Println(branch)
	fmt.Println()
	if fixed > 0 {
		fmt.Println("Ready for review.")
	} else {
		fmt.Println("No successful fixes were kept.")
	}
	fmt.Println("--------------------------------------------------")
}
