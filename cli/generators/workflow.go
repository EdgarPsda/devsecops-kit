package generators

import (
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/EdgarPsda/devsecops-kit/cli/templates"
)

func GenerateGithubActions(cfg *InitConfig) error {
	var tmplName string

	switch cfg.Project.Language {
	case "nodejs":
		tmplName = "workflows/node_security.yml.tmpl"
	case "golang":
		tmplName = "workflows/go_security.yml.tmpl"
	default:
		return fmt.Errorf("no workflow template for language: %s", cfg.Project.Language)
	}

	tmplData, err := templates.TemplateFS.ReadFile(tmplName)
	if err != nil {
		return fmt.Errorf("failed reading embedded template %s: %w", tmplName, err)
	}

	tmpl, err := template.New("workflow").Parse(string(tmplData))
	if err != nil {
		return fmt.Errorf("failed parsing template: %w", err)
	}

	outPath := filepath.Join(".github", "workflows", "security.yml")
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create workflow file: %w", err)
	}
	defer f.Close()

	return tmpl.Execute(f, cfg)
}
