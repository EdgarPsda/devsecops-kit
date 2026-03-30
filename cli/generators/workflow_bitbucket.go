package generators

import (
	"fmt"
	"os"
	"text/template"

	"github.com/edgarpsda/devsecops-kit/cli/templates"
)

func GenerateBitbucketPipelines(cfg *InitConfig) error {
	var tmplName string

	switch cfg.Project.Language {
	case "nodejs":
		tmplName = "ci/bitbucket/node_security.yml.tmpl"
	case "golang":
		tmplName = "ci/bitbucket/go_security.yml.tmpl"
	case "python":
		tmplName = "ci/bitbucket/python_security.yml.tmpl"
	case "java":
		tmplName = "ci/bitbucket/java_security.yml.tmpl"
	default:
		return fmt.Errorf("no Bitbucket Pipelines template for language: %s", cfg.Project.Language)
	}

	tmplData, err := templates.TemplateFS.ReadFile(tmplName)
	if err != nil {
		return fmt.Errorf("failed reading embedded template %s: %w", tmplName, err)
	}

	tmpl, err := template.New("bitbucket-pipelines").Parse(string(tmplData))
	if err != nil {
		return fmt.Errorf("failed parsing template: %w", err)
	}

	f, err := os.Create("bitbucket-pipelines.yml")
	if err != nil {
		return fmt.Errorf("failed to create bitbucket-pipelines.yml: %w", err)
	}
	defer f.Close()

	return tmpl.Execute(f, cfg)
}
