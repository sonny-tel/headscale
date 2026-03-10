// Package docs provides embedded documentation markdown files.
package docs

import "embed"

// Content holds all the markdown documentation files.
//
//go:embed *.md about/*.md ref/*.md ref/integration/*.md setup/*.md setup/install/*.md usage/*.md usage/connect/*.md
var Content embed.FS
