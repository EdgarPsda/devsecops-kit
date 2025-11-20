package generators

import (
	"fmt"
	"os"
	"text/template"

	"github.com/EdgarPsda/devsecops-kit/cli/templates"
)

func GenerateSecurityConfig(cfg *InitConfig) error {
	const tmplName = "security-config.yml.tmpl"

	tmplData, err := templates.TemplateFS.ReadFile(tmplName)
	if err != nil {
		return fmt.Errorf("failed reading embedded config template: %w", err)
	}

	tmpl, err := template.New("security-config").Parse(string(tmplData))
	if err != nil {
		return fmt.Errorf("failed parsing template: %w", err)
	}

	f, err := os.Create("security-config.yml")
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer f.Close()

	return tmpl.Execute(f, cfg)
}
