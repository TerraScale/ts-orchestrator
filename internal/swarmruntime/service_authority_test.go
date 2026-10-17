package swarmruntime

import (
	"context"
	"errors"
	"testing"

	"github.com/moby/swarmkit/v2/api"
)

func TestSignedServiceFinalMutationGuard(t *testing.T) {
	revoked := errors.New("current authority revoked")
	client := guardedServiceClient{guard: func(context.Context) error { return revoked }}
	for _, test := range []struct {
		name   string
		mutate func(context.Context) error
	}{
		{"create-floor", func(ctx context.Context) error {
			_, err := client.CreateConfig(ctx, &api.CreateConfigRequest{})
			return err
		}},
		{"update-floor", func(ctx context.Context) error {
			_, err := client.UpdateConfig(ctx, &api.UpdateConfigRequest{})
			return err
		}},
		{"create-service", func(ctx context.Context) error {
			_, err := client.CreateService(ctx, &api.CreateServiceRequest{})
			return err
		}},
		{"update-service", func(ctx context.Context) error {
			_, err := client.UpdateService(ctx, &api.UpdateServiceRequest{})
			return err
		}},
		{"rollback", func(ctx context.Context) error {
			_, err := client.UpdateService(ctx, &api.UpdateServiceRequest{Rollback: api.UpdateServiceRequest_PREVIOUS})
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			// A missing underlying client also proves the mutation was never reached.
			if err := test.mutate(t.Context()); !errors.Is(err, revoked) {
				t.Fatalf("mutation escaped current authority: %v", err)
			}
		})
	}
}

func TestServiceIntentGeneration(t *testing.T) {
	intent := serviceIntent()
	intent.Generation = 7
	spec, err := intent.serviceSpec()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := serviceIntentFingerprint(spec)
	if err != nil {
		t.Fatal(err)
	}
	intent.intentFingerprint = fingerprint
	labels := map[string]string{LabelIntentGeneration: "7", labelIntentFingerprint: fingerprint}
	if err := checkIntentGeneration(labels, intent); err != nil {
		t.Fatal(err)
	}
	changed := spec.Copy()
	changed.GetReplicated().Replicas++
	changed.Annotations.Labels[LabelOperationID] = "another-operation"
	if actual, err := serviceIntentFingerprint(changed); err != nil || actual != fingerprint {
		t.Fatalf("manager scale or operation changed workload identity: %q %v", actual, err)
	}
	for _, stored := range []string{"8", "07", "0", "bad"} {
		labels[LabelIntentGeneration] = stored
		if err := checkIntentGeneration(labels, intent); err == nil {
			t.Fatalf("accepted stale or malformed delivery generation %q", stored)
		}
	}
	labels[LabelIntentGeneration] = "7"
	intent.intentFingerprint = "changed-workload"
	if err := checkIntentGeneration(labels, intent); err == nil {
		t.Fatal("same generation admitted another workload")
	}
	intent.Generation++
	if err := checkIntentGeneration(labels, intent); err != nil {
		t.Fatal(err)
	}
}
