package region

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/registry/pullauth"
)

// ReleaseSnapshot copies descriptive metadata for comparison after renewal.
// It grants no current authority; callers must Check the fresh complete set.
func (v NetBirdComponents) ReleaseSnapshot() [3]NetBirdComponent {
	if v.state == nil {
		return [3]NetBirdComponent{}
	}
	return v.state.components
}

// ResolvePull rereads CURRENT for one member of the complete verified set.
// Credentials remain memory-only and bound to their exact registry origin.
func (v NetBirdComponents) ResolvePull(ctx context.Context, role string) (pullauth.PullCredentials, error) {
	if err := v.Check(ctx); err != nil {
		return pullauth.PullCredentials{}, err
	}
	s := v.state
	ctx, cancel := context.WithDeadline(ctx, s.expires)
	defer cancel()
	for _, component := range s.components {
		if component.role != role {
			continue
		}
		pulls, err := pullauth.NewPullSecrets(s.factory)
		if err != nil {
			return pullauth.PullCredentials{}, err
		}
		credentials, err := pulls.Resolve(s.requestContext(ctx, &component.issuer), component.pull, component.pull.Scope, component.pull.Secret)
		if err != nil {
			return pullauth.PullCredentials{}, err
		}
		if err := v.Check(ctx); err != nil {
			return pullauth.PullCredentials{}, err
		}
		return credentials, nil
	}
	return pullauth.PullCredentials{}, errNetBirdComponents
}
