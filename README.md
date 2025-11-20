# DevSecOps Kit

Opinionated CLI to bootstrap a complete security pipeline for small teams.

DevSecOps Kit automatically detects your project type and generates a ready-to-use GitHub Actions security workflow along with a centralized `security-config.yml`.

It’s designed for small teams, freelancers, and agencies that need practical DevSecOps pipelines — without spending days wiring scanners manually.

---

## ✨ Features (v0.1.0)

### 🔍 Automatic Project Detection
- Node.js (via `package.json`)
- Go (via `go.mod`)

### ⚙️ Security Workflow Generation
Creates a tailored GitHub Actions workflow:
- Node.js workflow
- Go workflow

### 🛡️ Security Tools Integration
Enable tools individually via CLI flags:
- **Semgrep** — static code analysis  
- **Gitleaks** — secrets scanning  
- **Trivy** — dependency & container scanning  

### 🎚️ Configurable Severity Threshold
Controls what fails the pipeline:  
`low | medium | high | critical`

### 📄 Centralized Security Configuration
Automatically creates a `security-config.yml` with:
- Language / framework  
- Enabled tools  
- Severity threshold  
- Metadata (CLI version, timestamp)

### 📦 Single Self-Contained Binary
- No external templates needed  
- All assets embedded via `go:embed`

---

## 🛠️ Installation

You can install DevSecOps Kit in two ways:

### **1. Install via Go (recommended)**

```bash
go install github.com/edgarposada/devsecops-kit@latest
```

This installs the binary globally into `$GOPATH/bin/`.

Check that it works:

```bash
devsecops version
```

### **2. Build from source**

```bash
git clone https://github.com/edgarposada/devsecops-kit.git
cd devsecops-kit

# Build binary (VERSION defaults to 0.1.0)
make build

# Check version
./devsecops-kit version
```

---

## 🚀 Usage

### Initialize security settings

```bash
devsecops init
```

This will:

- Detect Node.js or Go  
- Generate `security-config.yml`  
- Create `.github/workflows/security.yml`  
- Enable default scanners (Semgrep + Gitleaks)

---

## 🔧 CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--tools` | Comma-separated list: `semgrep`, `gitleaks`, `trivy` | `semgrep,gitleaks` |
| `--severity` | Minimum severity to fail CI | `high` |
| `--output` | Output directory | `./` |
| `--dry-run` | Preview without generating files | `false` |
| `-y, --yes` | Skip confirmation prompts | `false` |
| `--version` | Show version | — |

---

## 📝 Usage Examples

### 1. Basic initialization
```bash
devsecops init
```

### 2. Enable all tools
```bash
devsecops init --tools semgrep,gitleaks,trivy
```

### 3. Fail on ANY severity
```bash
devsecops init --severity low
```

### 4. Strict performance mode (fail only critical)
```bash
devsecops init --severity critical
```

### 5. Preview before generating (dry run)
```bash
devsecops init --dry-run
```

### 6. Custom output folder
```bash
devsecops init --output ./ci/security
```

### 7. Non-interactive mode (CI-friendly)
```bash
devsecops init -y
```

---

## 📄 Example Configurations

### Node.js example (`security-config.yml`)

```yaml
language: node
tools:
  semgrep: true
  gitleaks: true
  trivy: true
severity_threshold: high

metadata:
  generated_at: 2025-01-01T12:34:56Z
  version: 0.1.0
```

### Go example

```yaml
language: go
tools:
  semgrep: true
  gitleaks: true
  trivy: true
severity_threshold: high

metadata:
  generated_at: 2025-01-01T12:34:56Z
  version: 0.1.0
```

---

## ⚙️ Example GitHub Actions Workflow

### Node.js Version

```yaml
name: Security Scan

on:
  push:
    branches: ["main"]
  pull_request:

jobs:
  security:
    name: Run Security Scans
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: "18"

      - name: Install dependencies
        run: npm install --legacy-peer-deps

      - name: Semgrep Code Scan
        uses: returntocorp/semgrep-action@v1
        with:
          config: "p/ci"

      - name: Secrets Scan (Gitleaks)
        uses: gitleaks/gitleaks-action@v2
        with:
          args: "--config-path=.gitleaks.toml --verbosity=info"

      - name: Dependency Scan (Trivy)
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: "fs"
          severity: "HIGH,CRITICAL"
```

---

### Go Version

```yaml
name: Security Scan

on:
  push:
    branches: ["main"]
  pull_request:

jobs:
  security:
    name: Run Security Scans
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: "1.22"

      - name: Semgrep Code Scan
        uses: returntocorp/semgrep-action@v1
        with:
          config: "p/ci"

      - name: Secrets Scan (Gitleaks)
        uses: gitleaks/gitleaks-action@v2

      - name: Dependency Scan (Trivy)
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: "fs"
          severity: "HIGH,CRITICAL"
```

---

## 🧭 Roadmap

| Version | Planned Feature |
|---------|-----------------|
| **v0.2.0** | Prebuilt binaries for Mac, Linux, Windows |
| **v0.3.0** | Python, Java & Dockerfile detection |
| **v0.4.0** | Local CLI command to run all scans |
| **v0.5.0** | VS Code extension for workflow generation |
| **v1.0.0** | Fully interactive onboarding wizard |

---

## 🤝 Contributing

Contributions are welcome.

1. Fork the repo  
2. Create a feature branch  
3. Run `make build` before submitting  
4. Open a PR following conventional commits  

---

## 🧪 Development

### Build:
```bash
make build
```

### Tests:
```bash
make test
```

### Formatting:
```bash
make fmt
```

---

## ❓ FAQ

### Is it only for GitHub Actions?
For now, yes. GitLab & Jenkins support are planned.

### Will it overwrite my workflows?
No. It creates new files unless you pass `--yes`.

### Does it send telemetry?
Never. No tracking. 100% local.
