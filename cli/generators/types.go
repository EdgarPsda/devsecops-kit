// cli/generators/types.go
package generators

import "github.com/edgarpsda/devsecops-kit/cli/detectors"

type ToolsConfig struct {
	Semgrep  bool
	Trivy    bool
	Gitleaks bool
}

type InitConfig struct {
	Project           *detectors.ProjectInfo
	SeverityThreshold string
	Tools             ToolsConfig
}
