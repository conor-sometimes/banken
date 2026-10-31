package main

import "embed"

// embeddedRules carries banken's baseline rule tree compiled into the binary,
// so a fresh install detects threats with zero configuration -- no rules need
// to be placed on disk first. On-disk rule trees (the -rules flag / config)
// are loaded on top of this baseline and win on a name clash, so operators
// extend or override it without losing the defaults.
//
//go:embed rules
var embeddedRules embed.FS
