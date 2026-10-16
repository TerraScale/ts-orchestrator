package cli

import (
	"context"
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
) <-chan deploymentPreflightResult {
	results := make(chan deploymentPreflightResult)
	go func() {
		defer close(results)
		inspected := make(map[string]binaryReceipt)
		var inspection sync.Mutex
		var regions errgroup.Group
		regions.SetLimit(4)
		for _, cell := range cells {
			regions.Go(func() error {
				ctx, cancel := context.WithTimeout(c.ctx, budget)
				defer cancel()
				regional := c
				regional.ctx = ctx
				target := deploymentTarget{cell: cell, environment: environment, architectures: architectures}
				admit := func() error {
					if target.environment == "" || len(target.architectures) == 0 {
						location, err := channelLocation(env, cell, namespace)
						if err != nil {
							return err
						}
						scope, err := deploymentScope(ctx, location, cell)
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
					if err := regional.verifyProductionArtifacts(evidenceDir, roots, cell, target.environment, target.binaries, time.Now().UTC().Add(budget)); err != nil {
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
				err := admit()
				if err != nil {
					err = fmt.Errorf("%s: %w", cell, err)
					fmt.Fprintf(progress, "%s qualification refused: %v\n", cell, err)
				}
				select {
				case results <- deploymentPreflightResult{target, err}:
				case <-c.ctx.Done():
				}
				return nil
			})
		}
		_ = regions.Wait()
	}()
	return results
}

type deploymentPreflightResult struct {
	target deploymentTarget
	err    error
}
