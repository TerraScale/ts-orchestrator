package runtimepriority

import (
	"context"
)

type Runner struct {
	Manifest, State Object
	EvidenceDir     string
	AdapterCall     func(context.Context, Object) (Object, error)
}
