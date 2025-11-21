# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),  
and this project adheres (loosely) to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

- TBD

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
