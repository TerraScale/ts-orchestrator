package cli

import (
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

type deploymentTarget struct {
	cell          string
	environment   string
	architectures []string
	binaries      map[string]binaryReceipt
	location      releasechannel.Location
}

// Admit independently before retrieving any signing credentials.
func (c command) prepareDeploymentTargets(directory, evidenceDir, namespace, environment string,
	cells, architectures []string, qualification release.Qualification, qualificationDigest string,
	roots trust.Keyring, budget time.Duration, env deployEnv, progress io.Writer,
) ([]deploymentTarget, []error) {
	targets := make([]deploymentTarget, len(cells))
	failures := make([]error, len(cells))
	inspected := make(map[string]binaryReceipt)
	var inspection sync.Mutex
	var regions errgroup.Group
	regions.SetLimit(4)
	for index, cell := range cells {
		regions.Go(func() error {
			target := deploymentTarget{cell: cell, environment: environment, architectures: architectures}
			admit := func() error {
				if target.environment == "" || len(target.architectures) == 0 {
					location, err := channelLocation(env, cell, namespace)
					if err != nil {
						return err
					}
					scope, err := deploymentScope(c.ctx, location, cell)
					if err != nil {
						return err
					}
					if target.environment == "" {
						target.environment = scope.Environment
					}
					if len(target.architectures) == 0 {
						target.architectures = scope.Architectures
					}
					target.location = location
				}
				target.binaries = make(map[string]binaryReceipt, len(target.architectures))
				for _, architecture := range target.architectures {
					inspection.Lock()
					receipt, found := inspected[architecture]
					var err error
					if !found {
						receipt, err = env.inspect(binaryPath(directory, architecture), qualification.GoVersion, qualification.SourceRevision)
						if err == nil {
							inspected[architecture] = receipt
						}
					}
					inspection.Unlock()
					if err != nil {
						return err
					}
					receipt.QualificationSHA256 = qualificationDigest
					if err := qualification.MatchBinary(receipt, qualificationDigest); err != nil {
						return err
					}
					if receipt.GOARCH != architecture {
						return fmt.Errorf("%s binary is built for %s", architecture, receipt.GOARCH)
					}
					target.binaries[architecture] = receipt
				}
				if err := c.verifyProductionArtifacts(evidenceDir, roots, cell, target.environment, target.binaries, time.Now().UTC().Add(budget)); err != nil {
					return err
				}
				if target.location.Client == nil {
					location, err := channelLocation(env, cell, namespace)
					if err != nil {
						return err
					}
					target.location = location
				}
				return nil
			}
			if err := admit(); err != nil {
				failures[index] = fmt.Errorf("%s: %w", cell, err)
				fmt.Fprintf(progress, "%s qualification refused: %v\n", cell, err)
			} else {
				targets[index] = target
			}
			return nil
		})
	}
	_ = regions.Wait()
	admitted := targets[:0]
	for _, target := range targets {
		if target.binaries != nil {
			admitted = append(admitted, target)
		}
	}
	return admitted, failures
}
