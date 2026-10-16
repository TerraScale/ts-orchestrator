//go:build fixturetest

package swarmruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/moby/swarmkit/v2/agent/exec"
)

// StartAcceptedNodeFixture retains signed current authority and accepted launch
// pins while substituting the state directory and concrete OCI SDK observer.
// It does not initialize the instance-principal home IAM enrollment authority.
func StartAcceptedNodeFixture(ctx context.Context, stateDir string,
	reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity,
	foundations region.FoundationResolver, vault vaultsecret.VaultClient, bundles vaultsecret.BundleClient,
	executor exec.Executor, observer *bootstrapstart.OCIInstanceObserver, hostEnrollment []byte,
) (*Node, error) {
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir || stateDir == "/" || observer == nil || vault == nil || bundles == nil {
		return nil, errors.New("accepted manager fixture requires an isolated directory and concrete OCI clients")
	}
	authority, err := reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	identity := authority.Identity()
	foundation, err := foundations.Resolve(ctx, strings.ToUpper(identity.Cell))
	if err != nil {
		return nil, err
	}
	if foundation.OCIRegion != authority.Anchor().Anchor().OCIRegion {
		return nil, errors.New("fixture foundation differs from signed regional authority")
	}
	target, err := foundation.VaultTarget()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(hostEnrollment)
	if hex.EncodeToString(digest[:]) != accepted.LaunchMaterialSHA256[bootstrapstart.HostEnrollmentFilename] {
		return nil, errors.New("fixture enrollment differs from accepted launch pin")
	}
	bundle, err := hostenroll.ParsePublicBundle(hostEnrollment)
	if err != nil {
		return nil, err
	}
	if bundle.MatchesImageLayout() != nil || bundle.Cell != strings.ToLower(identity.Cell) || bundle.Region != identity.Cell || bundle.Environment != identity.Environment {
		return nil, errors.New("fixture enrollment differs from signed runtime scope")
	}
	public, err := bundle.ResponsePublicKey()
	if err != nil {
		return nil, err
	}
	refresh := func(ctx context.Context) error {
		current, err := reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
		if err != nil {
			return err
		}
		if current.Identity() != identity {
			return errors.New("fixture runtime authority changed")
		}
		fresh, err := foundations.Resolve(ctx, strings.ToUpper(identity.Cell))
		if err != nil {
			return err
		}
		freshTarget, err := fresh.VaultTarget()
		if err != nil {
			return err
		}
		if fresh.OCIRegion != foundation.OCIRegion || freshTarget != target {
			return errors.New("fixture regional Vault foundation changed")
		}
		return nil
	}
	n, err := startAcceptedNodeAt(ctx, stateDir, identity, target, vault, bundles, executor, refresh)
	if err != nil {
		return nil, err
	}
	n.workerAuthority = &workerAuthority{identity: identity, public: public, target: target, vault: vault, bundles: bundles, observer: observer, refresh: refresh}
	return n, nil
}
