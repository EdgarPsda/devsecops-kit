# 📘 DevSecOps Kit

Modern, opinionated CLI to bootstrap a complete security pipeline for small teams — instantly.
DevSecOps Kit detects your project (Node.js or Go), generates a hardened GitHub Actions workflow, and produces a centralized security configuration that evolves with your needs.

Designed for small teams, freelancers, and agencies who need practical DevSecOps without complexity.

## 🚀 Key Features (v0.2.0)

### 🔍 Automatic Project Detection
Works out-of-the-box with:

- Node.js (`package.json`)
- Go (`go.mod`)

### ⚙️ Auto-Generated Security Pipeline
Generates a ready-to-run GitHub Actions workflow including:

- Semgrep (SAST)
- Gitleaks (Secrets detection)
- Trivy (FS + dependency scanning)
- Hardenered permissions
- Artifact uploads
- Timeout protections

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
  trivy-fs.json
  summary.json
```

The `summary.json` contains:

- Total secrets leaks
- Vulnerability counts by severity
- Ready for dashboards or fail-gates in future releases

### 💬 Automated PR Security Comment
Every pull request receives a concise, updated comment summarizing:

- Secrets found
- Vulnerabilities
- PASS/FAIL recommendation

### 📄 Expanded Configuration (v0.2.0)

Generated automatically as:

```yaml
version: "0.2.0"

language: "golang"
framework: ""

severity_threshold: "high"

tools:
  semgrep: true
  trivy: true
  gitleaks: true

exclude_paths: []
fail_on: {}

notifications:
  pr_comment: true
  slack: false
  email: false
```

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

| Version | Features |
|---------|----------|
| **0.3.0** | Fail-on logic, exclude-paths integration, Semgrep JSON support |
| **0.4.0** | Local CLI scans (`devsecops scan`) |
| **0.5.0** | Expanded detection: Python, Java, Dockerfiles |
| **1.0.0** | Full onboarding experience + multi-CI support |

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
