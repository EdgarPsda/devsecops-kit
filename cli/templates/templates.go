package templates

import "embed"

//go:embed workflows/*.tmpl
//go:embed ci/gitlab/*.tmpl
//go:embed ci/bitbucket/*.tmpl
//go:embed security-config.yml.tmpl
var TemplateFS embed.FS
