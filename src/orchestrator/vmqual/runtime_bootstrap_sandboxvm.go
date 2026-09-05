//go:build sandboxvm

package vmqual

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
)

// activateGuest performs the initial version switches through ts-node's durable
// command journal. It never writes symlinks or calls a guest lifecycle in process.
// This uses the isolated qualification transport; it does not establish GRU fencing.
func (factory *firecrackerFactory) activateGuest(ctx context.Context, host string) error {
	vm, err := factory.activeDeliveryVM(host)
	if err != nil {
		return err
	}
	bootstrap, _, err := factory.services.Bootstrap(vm.guest)
	if err != nil {
		return err
	}
	manifest, err := hostagent.ParseHostManifest(bootstrap.DesiredHostManifest)
	if err != nil {
		return err
	}
	return factory.activateAdmittedGuest(ctx, host, manifest)
}

func (factory *firecrackerFactory) activateAdmittedGuest(ctx context.Context, host string, manifest hostagent.HostManifest) error {
	digest, err := hostagent.HostManifestSha256(manifest)
	if err != nil {
		return err
	}
	node, err := hostagent.NewNodeId(host)
	if err != nil {
		return err
	}
	activation, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var report hostagent.NodeStatusReport
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		report, err = factory.nodeStatus(activation, host, "initial-status")
		if err == nil {
			ready, validateErr := initialActivationStatus(report, manifest, digest)
			if validateErr != nil {
				return validateErr
			}
			if ready {
				break
			}
		}
		select {
		case <-activation.Done():
			return fmt.Errorf("vmqual: initial signed host installation unavailable: %w", errors.Join(activation.Err(), err))
		case <-ticker.C:
		}
	}
	pending := false
	for _, fact := range report.Facts.Components {
		pending = pending || fact.Version == ""
	}
	if !pending && report.State == hostagent.NodeStateServing {
		return nil
	}
	identity := sha256.Sum256([]byte(host + "\n" + digest))
	prefix := "vmq-init-" + hex.EncodeToString(identity[:12])
	drainSubject, _ := hostagent.NodeDrainSubject(node)
	drain := func(suffix string, enabled bool) error {
		command, commandErr := hostagent.NewDrainCommand(prefix+suffix, enabled)
		if commandErr != nil {
			return commandErr
		}
		var receipt hostagent.DrainReceipt
		if err := factory.requestTSNode(activation, host, drainSubject, command, &receipt); err != nil {
			return err
		}
		if receipt.CommandId != command.CommandId || receipt.NodeId != host || receipt.Draining != enabled || enabled && !receipt.Quiesced {
			return errors.New("vmqual: initial activation drain receipt is inconsistent")
		}
		return nil
	}
	subject, _ := hostagent.NodeDeploySubject(node)
	for _, component := range manifest.Components {
		current := ""
		for _, fact := range report.Facts.Components {
			if fact.Name == component.Name {
				current = fact.Version
			}
		}
		if current == component.Version {
			continue
		}
		if err := drain("-drain-"+component.Name, true); err != nil {
			return err
		}
		quiesced, err := factory.nodeStatus(activation, host, "initial-quiesce")
		if err != nil {
			return err
		}
		ready, err := initialActivationStatus(quiesced, manifest, digest)
		if err != nil {
			return err
		}
		if !ready || !quiesced.Quiesced || quiesced.State == hostagent.NodeStateServing {
			return errors.New("vmqual: initial activation requires verified quiescence")
		}

		command, err := hostagent.NewDeployCommand(prefix+"-"+component.Name, component.Name, component.Version)
		if err != nil {
			return err
		}
		var receipt hostagent.DeployReceipt
		if err := factory.requestTSNode(activation, host, subject, command, &receipt); err != nil {
			return err
		}
		if receipt.CommandId != command.CommandId || receipt.NodeId != host || !receipt.Accepted || receipt.Current != component.Version {
			return fmt.Errorf("vmqual: ts-node refused initial %s activation", component.Name)
		}
	}
	if err := drain("-release", false); err != nil {
		return err
	}
	report, err = factory.nodeStatus(activation, host, "initial-activated")
	if err != nil {
		return err
	}
	ready, err := initialActivationStatus(report, manifest, digest)
	if err != nil {
		return err
	}
	if !ready || report.State != hostagent.NodeStateServing || report.Quiesced {
		return errors.New("vmqual: initial activation did not reach serving host state")
	}
	for _, fact := range report.Facts.Components {
		if fact.Version != fact.Desired || !fact.UnitActive {
			return fmt.Errorf("vmqual: activated %s process is not running", fact.Name)
		}
	}
	return nil
}

func initialActivationStatus(report hostagent.NodeStatusReport, manifest hostagent.HostManifest, digest string) (bool, error) {
	if report.Facts.ManifestSha256 != digest {
		return false, errors.New("vmqual: guest initial manifest differs from the admitted seed")
	}
	if len(report.Facts.Components) != len(manifest.Components) {
		return false, errors.New("vmqual: guest initial component set differs from the admitted seed")
	}
	ready := true
	seen := make(map[string]bool)
	for _, fact := range report.Facts.Components {
		if seen[fact.Name] {
			return false, errors.New("vmqual: duplicate initial component observation")
		}
		seen[fact.Name] = true
		found := false
		for _, spec := range manifest.Components {
			if spec.Name != fact.Name {
				continue
			}
			found = true
			if fact.Desired != spec.Version || fact.Version != "" && fact.Version != spec.Version {
				return false, errors.New("vmqual: initial activation refuses an unexpected serving or desired release")
			}
		}
		if !found {
			return false, errors.New("vmqual: unexpected initial component observation")
		}
		ready = ready && fact.Installed
	}
	return ready, nil
}
