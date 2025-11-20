# DevSecOps Kit

> Opinionated CLI to bootstrap a sane security pipeline for small teams.

**DevSecOps Kit** detects your project (Node.js or Go for now) and generates:

- A ready-to-run **GitHub Actions security workflow**
- A `security-config.yml` that captures:
  - Severity threshold
  - Which tools are enabled (Semgrep, Trivy, Gitleaks)

The goal is to make it easy for **small teams, freelancers and agencies** to adopt DevSecOps practices without spending days wiring scanners manually.

---

## ✨ Features (v0.1.0)

- 🔍 **Auto-detect project type**
  - Node.js (via `package.json`)
  - Go (via `go.mod`)
- ⚙️ **Scaffold a security workflow for GitHub Actions**
  - Node.js workflow
  - Go workflow
- 🛡️ **Choose your tools (via flags)**
  - [Semgrep](https://semgrep.dev/)
  - [Gitleaks](https://github.com/gitleaks/gitleaks)
  - [Trivy](https://github.com/aquasecurity/trivy)
- 🎚️ **Set severity threshold**
  - `low`, `medium`, `high`, `critical`
- 📄 **Generate a `security-config.yml`**
  - Captures language, framework, severity, tools enabled
- 📦 **Single self-contained binary**
  - Templates are embedded via `go:embed` (no extra files needed)

---

## 🚀 Getting Started

### 1. Install

For now (v0.1.0), build from source:

```bash
git clone https://github.com/edgarposada/devsecops-kit.git
cd devsecops-kit

# Build binary (defaults to VERSION=0.1.0)
make build

# Check version
./devsecops version
