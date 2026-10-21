package ociregion

import _ "embed"

//go:embed sjc-1-plan.json
var foundationTemplate string

// FoundationTemplate is the single reviewed regional platform template.
func FoundationTemplate() string { return foundationTemplate }
