package registry

import (
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/registry/pullauth"
)

var ErrPullAuth = pullauth.ErrPullAuth

type PullScope = pullauth.PullScope
type PullSecret = pullauth.PullSecret
type PullClaim = pullauth.PullClaim
type PullSecrets = pullauth.PullSecrets
type PullCredentials = pullauth.PullCredentials

func NewPullSecrets(factory *ociclient.Factory) (*PullSecrets, error) {
	return pullauth.NewPullSecrets(factory)
}
