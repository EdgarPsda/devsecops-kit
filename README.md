# 📘 DevSecOps Kit

Modern, opinionated CLI to bootstrap a complete security pipeline for small teams — instantly.
DevSecOps Kit detects your project (Node.js or Go), generates a hardened GitHub Actions workflow, and produces a centralized security configuration that evolves with your needs.

Designed for small teams, freelancers, and agencies who need practical DevSecOps without complexity.

## 🚀 Key Features (v0.3.0)

### 🔍 Automatic Project Detection
Works out-of-the-box with:

- Node.js (`package.json`)
- Go (`go.mod`)
- **Docker** (Dockerfile detection) 🆕

### ⚙️ Auto-Generated Security Pipeline
Generates a ready-to-run GitHub Actions workflow including:

- Semgrep (SAST)
- Gitleaks (Secrets detection)
- Trivy (FS + dependency scanning)
- **Trivy Image Scanning** (when Dockerfile present) 🆕
- Hardened permissions
- Artifact uploads
- Timeout protections

### 🎯 Config-Driven Fail Gates 🆕
Define thresholds that automatically fail CI builds:

```yaml
fail_on:
  gitleaks: 0           # Fail if ANY secrets detected
  semgrep: 10           # Fail if 10+ findings
  trivy_critical: 0     # Fail if ANY critical vulnerabilities
  trivy_high: 5         # Fail if 5+ high severity vulnerabilities
```

### 🚫 Exclude Paths 🆕
Reduce noise by excluding directories from scans:

```yaml
exclude_paths:
  - "vendor/"
  - "node_modules/"
  - "test/"
  - "*.test.js"
```

### 💬 Inline "Fix-it" PR Comments 🆕
Get detailed, actionable feedback directly on your code:

- File/line-specific comments for security issues
- Remediation guidance for each finding
- References to security best practices
- Automatic comment placement on changed files only

### 🧙 Interactive Wizard
```bash
devsecops init --wizard
```

A guided setup for new users:

- Select tools
- Choose severity gates
- Preview settings before generating

### 🩺 Environment Diagnose Command
```bash
devsecops diagnose
```

Checks system readiness:

- Installed scanners
- Docker availability
- Project detection
- CI/CD compatibility

### 📦 Artifacts + JSON Summary (CI)
Each workflow produces:

```
artifacts/security/
  gitleaks-report.json
  semgrep-report.json
  trivy-fs.json
  trivy-image.json      # When Dockerfile present
  summary.json          # v0.3.0 schema
```

The `summary.json` contains:

- Total secrets leaks
- Vulnerability counts by severity
- **PASS/FAIL status based on thresholds** 🆕
- **Blocking issue count** 🆕

### 💬 Enhanced PR Security Comments 🆕
Every pull request receives:

1. **Summary Comment** (updated, not duplicated):
   - Secrets found
   - FS & Image vulnerabilities
   - **Clear PASS/FAIL status**
   - **Blocking issue count**

2. **Inline Fix-it Comments**:
   - Specific file/line comments
   - Remediation guidance
   - Security references

### 📄 Configuration (v0.3.0)

Generated automatically as:

```yaml
version: "0.3.0"

language: "golang"
framework: ""

severity_threshold: "high"

tools:
  semgrep: true
  trivy: true
  gitleaks: true

# Exclude paths from scanning (reduces noise)
exclude_paths:
  - "vendor/"
  - "node_modules/"
  - "test/"

# Fail gates - CI fails if thresholds exceeded
fail_on:
  gitleaks: 0           # Fail if ANY secrets detected
  semgrep: 10           # Fail if 10+ Semgrep findings
  trivy_critical: 0     # Fail if ANY critical vulnerabilities
  trivy_high: 5         # Fail if 5+ high severity vulnerabilities
  trivy_medium: -1      # Disabled (set to number to enable)
  trivy_low: -1         # Disabled

notifications:
  pr_comment: true
  slack: false
  email: false
```

**How to customize:**
1. Run `devsecops init` to generate the config
2. Edit `security-config.yml` to adjust thresholds and exclusions
3. Commit changes - they take effect on next CI run

## 🛠️ Installation

### Option A — Install via Go
```bash
go install github.com/edgarpsda/devsecops-kit/cmd/devsecops@latest
```

Verify:

```bash
devsecops version
```

### Option B — Build from source
```bash
git clone https://github.com/edgarpsda/devsecops-kit.git
cd devsecops-kit
make build
./devsecops version
```

## 🚦 Quick Start

### 1. Run the wizard (recommended)
```bash
devsecops init --wizard
```

### 2. Or non-interactive:
```bash
devsecops init
```

This generates:

```
security-config.yml
.github/workflows/security.yml
```

### 3. Diagnose environment
```bash
devsecops diagnose
```

## 🔧 CLI Flags

| Flag           | Description                         |
|----------------|-------------------------------------|
| `--wizard`     | Launch interactive configuration     |
| `--severity`   | Set severity threshold               |
| `--no-semgrep` | Disable Semgrep                      |
| `--no-gitleaks`| Disable Gitleaks                     |
| `--no-trivy`   | Disable Trivy                        |
| `--verbose`    | Verbose mode                         |

## 📄 Example Security Summary Comment (PR)

```markdown
### 🔐 DevSecOps Kit Security Summary

- **Gitleaks:** 0 leaks
- **Trivy vulnerabilities:**
  - CRITICAL: 0
  - HIGH: 2
  - MEDIUM: 7

✅ Status: No blocking issues detected.
```

## 📁 Example Artifacts

```
security-reports/
  trivy-fs.json
  gitleaks-report.json
  summary.json
```

## 🧭 Roadmap

| Version | Features | Status |
|---------|----------|--------|
| **0.3.0** | Config-driven fail gates, exclude paths, Docker detection, image scanning, inline PR comments | ✅ **Released** |
| **0.4.0** | Local CLI scans (`devsecops scan`), local report generation | 🚧 In Progress |
| **0.5.0** | Python/Java detection, expanded framework support | 📋 Planned |
| **1.0.0** | Full onboarding UX, multi-CI support (GitLab, Jenkins) | 📋 Planned |

## 🤝 Contributing

Contributions are welcome!

- Fork the repository  
- Create a feature branch  
- Run `make build` before submitting  
- Follow conventional commits  
- Open a PR 🎉

## 📜 License

MIT — free for personal and commercial use.

## 🛡️ Security & Privacy

- No telemetry  
- No tracking  
- No code uploads  
- All scans run locally or in your own CI  
- OSS tools with strong community support  

## ❓ FAQ

### Does it overwrite existing CI workflows?
No — unless you explicitly approve it.

### Does it support GitLab or Jenkins?
Coming soon (planned in v0.4.x).

### Will more languages be supported?
Yes, Python, Java, Dockerfile detection is planned for v0.5.0.
