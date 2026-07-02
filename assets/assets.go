package assets

import "embed"

//go:embed Containerfile entrypoint.sh
var FS embed.FS
