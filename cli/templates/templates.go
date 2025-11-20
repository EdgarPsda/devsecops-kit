package templates

import "embed"

//go:embed workflows/*.tmpl
//go:embed security-config.yml.tmpl
var TemplateFS embed.FS
