# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),  
and this project adheres (loosely) to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

- TBD

---

## [0.3.0] - 2025-01-XX

### Added

- **Config-driven fail gates** 🎯:
  - New `fail_on` configuration in `security-config.yml`
  - Define per-tool thresholds that fail CI builds:
    - `gitleaks`: Fail on secret count threshold (default: 0)
    - `semgrep`: Fail on finding count threshold (default: 10)
    - `trivy_critical`, `trivy_high`, `trivy_medium`, `trivy_low`: Fail on vulnerability counts
  - Set threshold to `-1` to disable specific gate
  - Workflow now exits with error code 1 when thresholds exceeded
  - Summary status shows `PASS` or `FAIL` based on thresholds

- **Exclude paths support** 🚫:
  - New `exclude_paths` configuration to reduce scanning noise
  - Applies to all enabled scanners:
    - Semgrep: Uses `--exclude` flags
    - Gitleaks: Generates `.gitleaks.toml` with path allowlist
    - Trivy: Uses `skip-dirs` parameter
  - Common exclusions: `vendor/`, `node_modules/`, `test/`, etc.

- **Dockerfile detection** 🐳:
  - Automatic detection of Dockerfile and docker-compose.yml
  - Added `HasDocker` and `DockerImages` fields to `ProjectInfo`
  - `devsecops detect` now shows Docker status
  - Parses Dockerfile to extract base images

- **Trivy image scanning** 📦:
  - Automatic Docker image scanning when Dockerfile detected
  - Builds temporary image (`devsecops-scan-temp:latest`) for scanning
  - Generates `trivy-image.json` artifact
  - Image vulnerabilities included in summary and PR comments
  - Same fail gates apply to both FS and image scans

- **Inline "Fix-it" PR comments** 💬:
  - Detailed, file/line-specific security comments on PRs
  - Semgrep findings:
    - Shows severity, rule ID, and message
    - Includes fix suggestions when available
    - Links to security references
  - Gitleaks findings:
    - Highlights secret location
    - Provides remediation steps
    - Warns about credential rotation
  - Only comments on changed files in the PR
  - Limited to 10 Semgrep + 5 Gitleaks comments per run (prevents spam)

- **Enhanced PR summary comments**:
  - Now shows clear **PASS/FAIL status** based on fail gates
  - Displays blocking issue count
  - Separate sections for Trivy FS and Trivy Image results
  - Idempotent updates (no duplicate comments)

- **Structured summary.json v0.3.0**:
  - New fields:
    - `status`: "PASS" or "FAIL"
    - `blocking_count`: Number of issues exceeding thresholds
    - `trivy_image`: Image scan results (when Dockerfile present)
  - Ready for dashboard integrations and trend analysis

### Changed

- **Updated `security-config.yml` schema to v0.3.0**:
  - Added comprehensive `fail_on` configuration with defaults
  - Added `exclude_paths` with commented examples
  - Updated version to `"0.3.0"`

- **Workflow templates enhanced**:
  - Added Python step to extract config (requires PyYAML)
  - Config extraction happens early in workflow
  - Fail gate check runs at end (after artifacts upload)
  - Both Go and Node.js templates updated identically

- **README updated**:
  - Highlighted v0.3.0 features with 🆕 badges
  - Added fail gates and exclude paths examples
  - Updated configuration section with full v0.3.0 schema
  - Added customization instructions
  - Updated roadmap with release status

### Fixed

- **PyYAML installation** added to config extraction step (fixes `ModuleNotFoundError`)
- **Dockerfile image extraction** now uses proper string parsing (not filepath.SplitList)
- **Build stage detection** in Dockerfiles (skips `FROM ... AS stage` lines)
- **Gitleaks JSON report generation** switched from `gitleaks-action` to direct CLI execution (enables fix-it comments to read findings)

---

## [0.2.0] - 2025-11-21

### Added

- **`devsecops diagnose` command** to verify environment readiness:
  - Checks installed scanners (Semgrep, Gitleaks, Trivy)
  - Verifies Docker availability (for Trivy)
  - Confirms project type detection
- **Interactive wizard** for initialization:
  - `devsecops init --wizard`
  - Guides users through selecting tools, severity thresholds, and configuration choices.
- **Automated PR security summary comment**:
  - GitHub Actions workflow posts (and updates) a comment on pull requests.
  - Comment includes Gitleaks leak counts, Trivy vulnerability counts, and a pass/fail recommendation.
- **JSON summary output**:
  - New `artifacts/security/summary.json` file generated on each run.
  - Includes:
    - Total number of leaks from Gitleaks (when available)
    - Aggregated Trivy vulnerabilities per severity (CRITICAL/HIGH/MEDIUM/LOW)
- **Security artifacts upload**:
  - Workflow now uploads a `security-reports` artifact containing:
    - `summary.json`
    - `trivy-fs.json` (when Trivy is enabled)
    - `gitleaks-report.json` (reserved for future enhancements)
- **Expanded `security-config.yml` schema**:
  - New fields added:
    - `version`: configuration schema version (starting at `"0.2.0"`)
    - `exclude_paths`: reserved list for future path exclusions
    - `fail_on`: reserved map for future per-tool fail gates
    - `notifications`:
      - `pr_comment`: enabled by default
      - `slack`, `email`: placeholders for future integrations

### Changed

- **GitHub Actions workflows hardened**:
  - Explicit `permissions` block:
    - `contents: read`
    - `issues: write`
    - `pull-requests: write`
  - Added job-level `timeout-minutes` to avoid hanging runs.
  - Ensured artifacts folder (`artifacts/security/`) is created early in the job.
- **Workflow templates updated** to:
  - Always generate `summary.json` even if some tools are disabled.
  - Use `actions/github-script@v7` to manage PR comments with an idempotent marker.
- **README** refreshed to reflect v0.2.0 features:
  - Added sections for wizard, diagnose, JSON summary, PR comments, and updated config format.
  - Clarified installation and quick-start flows.

### Fixed

- Resolved issues with:
  - Gitleaks GitHub token requirements on pull requests by setting `GITHUB_TOKEN` env in the workflow.
  - Incompatible `with:` inputs for the Gitleaks action (removed unsupported inputs).
  - `github-script` step script errors related to re-declaring `core` and insufficient `GITHUB_TOKEN` permissions.

---

## [0.1.0] - 2025-11-20

### Added

- Initial release of **DevSecOps Kit** CLI:
  - `devsecops` binary.
- **Project type detection**:
  - Node.js via `package.json`
  - Go via `go.mod`
- **GitHub Actions workflow generation**:
  - Node.js and Go workflows with:
    - Semgrep (SAST)
    - Gitleaks (secrets scanning)
    - Trivy (filesystem/dependency scanning)
- **`security-config.yml` generation**:
  - Base fields:
    - `language`
    - `framework`
    - `severity_threshold`
    - `tools` (Semgrep, Gitleaks, Trivy flags)
- **CLI flags for configuration**:
  - `--severity` to set severity threshold.
  - `--no-semgrep`, `--no-gitleaks`, `--no-trivy` to toggle tools.
- **Version subcommand**:
  - `devsecops version` prints the current CLI version.

---
