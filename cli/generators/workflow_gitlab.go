package generators

import (
	"fmt"
	"os"
	"text/template"

	"github.com/edgarpsda/devsecops-kit/cli/templates"
)

func GenerateGitLabCI(cfg *InitConfig) error {
	var tmplName string

	switch cfg.Project.Language {
	case "nodejs":
		tmplName = "ci/gitlab/node_security.yml.tmpl"
	case "golang":
		tmplName = "ci/gitlab/go_security.yml.tmpl"
	case "python":
		tmplName = "ci/gitlab/python_security.yml.tmpl"
	case "java":
		tmplName = "ci/gitlab/java_security.yml.tmpl"
	default:
		return fmt.Errorf("no GitLab CI template for language: %s", cfg.Project.Language)
	}

	tmplData, err := templates.TemplateFS.ReadFile(tmplName)
	if err != nil {
		return fmt.Errorf("failed reading embedded template %s: %w", tmplName, err)
	}

	tmpl, err := template.New("gitlab-ci").Parse(string(tmplData))
	if err != nil {
		return fmt.Errorf("failed parsing template: %w", err)
	}

	f, err := os.Create(".gitlab-ci.yml")
	if err != nil {
		return fmt.Errorf("failed to create .gitlab-ci.yml: %w", err)
	}
	defer f.Close()

	return tmpl.Execute(f, cfg)
}
