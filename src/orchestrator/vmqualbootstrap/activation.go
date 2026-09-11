package vmqualbootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"

	"net"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"time"
)

type Status func(context.Context, string, string) (hostagent.NodeStatusReport, error)
type Send func(context.Context, string, string, json.RawMessage, any) error

func Activate(ctx context.Context, host string, material Material, status Status, send Send) error {
	if ctx == nil || status == nil || send == nil {
		return errors.New("vmqual: bootstrap activation requires context and transports")
	}
	grant, err := hostagent.VerifyBootstrapGrant(host, material.PublicKeyPEM, material.SignedGrant)
	if err != nil {
		return err
	}
	manifest := grant.Manifest
	commands, err := hostagent.BootstrapCommands(grant)
	if err != nil {
		return err
	}
	digest, err := hostmanifest.HostManifestSha256(manifest)
	if err != nil {
		return err
	}
	// Measured quiet-host floor from instance start to a serving seed broker
	// is ~180 s (boot ~90 s, artifact downloads ~45 s, initial admission
	// ~45 s), and this clock starts as soon as the guest control channel
	// answers during early boot. The window must cover that chain with load
	// headroom.
	activation, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var report hostagent.NodeStatusReport
	var lastStatusError error
	var failures activationStatusFailures
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		report, err = status(activation, host, "initial-status")
		if err == nil {
			ready, validateErr := initialActivationStatus(report, manifest, digest)
			if validateErr != nil {
				return validateErr
			}
			if ready {
				break
			}
			lastStatusError = errors.New("guest reports desired signed artifacts not yet installed")
		} else {
			lastStatusError = failures.record(err, lastStatusError)
		}
		select {
		case <-activation.Done():
			return fmt.Errorf("vmqual: initial signed host installation unavailable (status failures: no-responders=%d authentication=%d timeout=%d other=%d): %w", failures.noResponders, failures.authentication, failures.timeout, failures.other, errors.Join(activation.Err(), lastStatusError))
		case <-ticker.C:
		}
	}
	pending := false
	for _, fact := range report.Facts.Components {
		pending = pending || fact.Version == ""
	}
	if !pending && report.State == hostagent.NodeStateServing {
		return activatedStatus(report, manifest, digest)
	}
	drain := func(step hostagent.BootstrapCommand, enabled bool) error {
		var command hostagent.DrainCommand
		if err := json.Unmarshal(step.Command, &command); err != nil {
			return err
		}
		var receipt hostagent.DrainReceipt
		if err := send(activation, host, step.Subject, step.Command, &receipt); err != nil {
			return err
		}
		if receipt.CommandId != command.CommandId || receipt.NodeId != host || receipt.Draining != enabled || enabled && !receipt.Quiesced {
			return errors.New("vmqual: initial activation drain receipt is inconsistent")
		}
		return nil
	}
	for index, component := range manifest.Components {
		current := ""
		for _, fact := range report.Facts.Components {
			if fact.Name == component.Name {
				current = fact.Version
			}
		}
		if current == component.Version {
			continue
		}
		if err := drain(commands[2*index], true); err != nil {
			return err
		}
		quiesced, err := status(activation, host, "initial-quiesce")
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

		step := commands[2*index+1]
		var command hostagent.DeployCommand
		if err := json.Unmarshal(step.Command, &command); err != nil {
			return err
		}
		var receipt hostagent.DeployReceipt
		if err := send(activation, host, step.Subject, step.Command, &receipt); err != nil {
			return err
		}
		if receipt.CommandId != command.CommandId || receipt.NodeId != host || !receipt.Accepted || receipt.Current != component.Version {
			return fmt.Errorf("vmqual: ts-node refused initial %s activation", component.Name)
		}
	}
	if err := drain(commands[len(commands)-1], false); err != nil {
		return err
	}
	report, err = status(activation, host, "initial-activated")
	if err != nil {
		return err
	}
	return activatedStatus(report, manifest, digest)
}

func activatedStatus(report hostagent.NodeStatusReport, manifest hostmanifest.HostManifest, digest string) error {
	ready, err := initialActivationStatus(report, manifest, digest)
	if err != nil {
		return err
	}
	if !ready || report.State != hostagent.NodeStateServing || report.Quiesced || !report.Facts.ClockMeasured || report.Facts.ClockUnhealthy {
		return errors.New("vmqual: initial activation did not reach serving host state with a healthy measured clock")
	}
	for _, fact := range report.Facts.Components {
		if fact.Version != fact.Desired || !fact.UnitActive {
			return fmt.Errorf("vmqual: activated %s process is not running", fact.Name)
		}
	}
	return nil
}

func initialActivationStatus(report hostagent.NodeStatusReport, manifest hostmanifest.HostManifest, digest string) (bool, error) {
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

// Fixed labels retain early failures when a final deadline obscures their cause.
type activationStatusFailures struct{ noResponders, authentication, timeout, other uint64 }

func (failures *activationStatusFailures) observe(err error) {
	var networkError net.Error
	switch {
	case errors.Is(err, nats.ErrNoResponders):
		failures.noResponders++
	case errors.Is(err, nats.ErrAuthorization):
		failures.authentication++
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, nats.ErrTimeout), errors.As(err, &networkError) && networkError.Timeout():
		failures.timeout++
	default:
		failures.other++
	}
}

func (failures *activationStatusFailures) record(err, previous error) error {
	timeouts := failures.timeout
	failures.observe(err)
	if previous != nil && (failures.timeout != timeouts || errors.Is(err, context.Canceled)) {
		return previous
	}
	return err
}
