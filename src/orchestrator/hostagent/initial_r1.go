package hostagent

import (
	"context"
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
)

// Admission applies to the complete immutable launch, including an older
// installed version selected by rollback or recovery.
func admitInitialComponents(ctx context.Context, specs []hostmanifest.ComponentSpec) error {
	for _, spec := range specs {
		if _, err := initialgrant.AdmitComponent(ctx, spec); err != nil {
			return err
		}
	}
	return nil
}

func withInitialLaunch(ctx context.Context, directory, component string, effect func(context.Context) error) error {
	spec, err := readComponentLaunch(directory, component)
	if err != nil {
		return err
	}
	admission, err := initialgrant.AdmitComponent(ctx, spec)
	if err != nil {
		return err
	}
	if admission == nil {
		return effect(ctx)
	}
	return admission.WithinMutation(ctx, effect)
}

// A retired predecessor may remain on disk if the process lost power before
// the replacement rename. The existing write-ahead command permits a receiver
// to await a fresh signed retry, but supplies no authority to run old units.
func (t *NatsTransport) hydrateRetiredInitialReceiver(digest string, admissionErr error) error {
	if !errors.Is(admissionErr, nodeauthority.ErrInitialR1Retired) {
		return admissionErr
	}
	pending, err := t.journal.pending()
	if err != nil {
		return err
	}
	for _, record := range pending {
		if record.Kind != commandKindManifest {
			continue
		}
		command, err := hostmanifest.ParseApplyManifestCommand(record.Request)
		if err != nil {
			return err
		}
		if command.ExpectedManifestSha256 != digest {
			continue
		}
		initial := false
		for _, spec := range command.Manifest.Components {
			_, candidate, err := initialgrant.ComponentConfig(spec)
			if err != nil {
				return err
			}
			initial = initial || candidate
		}
		if !initial {
			return t.lifecycle.HydrateDesired(nil)
		}
	}
	return admissionErr
}
