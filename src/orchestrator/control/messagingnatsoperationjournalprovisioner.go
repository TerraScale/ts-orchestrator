// Port of src/TerraScale.Orchestrator/Messaging/NatsOperationJournalProvisioner.cs.
package control

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// NatsOperationJournalProvisioner mirrors the C# static class: it runs before
// controllers start, using the separate infrastructure NATS identity.
var NatsOperationJournalProvisioner natsOperationJournalProvisioner

type natsOperationJournalProvisioner struct{}

// ProvisionAsync mirrors the C# ProvisionAsync.
func (natsOperationJournalProvisioner) ProvisionAsync(
	ctx context.Context,
	options *OrchestratorOptions,
) error {
	return natsOperationJournalProvisioner.provision(ctx, options, true)
}

// ProvisionControllerAsync mirrors the C# ProvisionControllerAsync.
func (natsOperationJournalProvisioner) ProvisionControllerAsync(
	ctx context.Context,
	options *OrchestratorOptions,
) error {
	return natsOperationJournalProvisioner.provision(ctx, options, false)
}

func (natsOperationJournalProvisioner) provision(
	ctx context.Context,
	options *OrchestratorOptions,
	includeAuthoritativeJournal bool,
) error {
	if options.InfrastructureNatsNKeyFile == nil || *options.InfrastructureNatsNKeyFile == "" {
		return errors.New("The infrastructure NATS identity is required to provision ORCH_OPERATIONS.")
	}

	if options.InfrastructureNatsTls == nil {
		return errors.New("Infrastructure mTLS is required to provision ORCH_OPERATIONS.")
	}

	client, err := nats.Connect(options.NatsUrl,
		nats.Timeout(15*time.Second),
		nats.MaxReconnects(0),
		natsNkeyOption(*options.InfrastructureNatsNKeyFile))
	if err != nil {
		return err
	}
	defer client.Close()

	if err := options.InfrastructureNatsTls.Options(); err != nil {
		_ = err
	}

	js, err := jetstream.New(client)
	if err != nil {
		return err
	}

	topology := NewNatsTopology(options.Cell, options.Replicas, options.Instance)
	if includeAuthoritativeJournal {
		return NatsOperationJournalProvisioner.ProvisionTopologyAsync(ctx, client, js, topology)
	}

	return NatsOperationJournalProvisioner.ProvisionControllerTopologyAsync(ctx, client, js, topology)
}

// ProvisionTopologyAsync mirrors the C# ProvisionTopologyAsync.
func (natsOperationJournalProvisioner) ProvisionTopologyAsync(
	ctx context.Context,
	client *nats.Conn,
	js jetstream.JetStream,
	topology *NatsTopology,
) error {
	if err := NatsOperationJournalProvisioner.ProvisionControllerTopologyAsync(ctx, client, js, topology); err != nil {
		return err
	}

	if _, err := NatsOperationJournalStore.ProvisionAsync(ctx, client, js, js, topology.Operations()); err != nil {
		return err
	}

	_, err := NatsOperationJournalStore.ProvisionAsync(
		ctx, client, js, js, topology.OperationProofConsumptions())
	return err
}

// ProvisionControllerTopologyAsync mirrors the C#
// ProvisionControllerTopologyAsync.
func (natsOperationJournalProvisioner) ProvisionControllerTopologyAsync(
	ctx context.Context,
	client *nats.Conn,
	js jetstream.JetStream,
	topology *NatsTopology,
) error {
	streams, err := topology.Streams()
	if err != nil {
		return err
	}

	for _, stream := range streams {
		if _, err := js.CreateOrUpdateStream(ctx, stream); err != nil {
			return err
		}
	}

	if _, err := js.CreateKeyValue(ctx, topology.Leaders()); err != nil {
		return err
	}

	if _, err := js.CreateKeyValue(ctx, topology.Runtime()); err != nil {
		return err
	}

	if _, err := js.CreateKeyValue(ctx, topology.Delivery()); err != nil {
		return err
	}

	bundles, err := natsOperationJournalOpenOrCreateObjectStore(ctx, js, topology.Bundles())
	if err != nil {
		return err
	}

	protocolPackage, err := natsOperationJournalOpenOrCreateObjectStore(
		ctx, js, topology.ProtocolPackage())
	if err != nil {
		return err
	}

	stored, err := protocolPackage.GetBytes(ctx, topology.ProtocolObject())
	if err != nil {
		if !errors.Is(err, jetstream.ErrObjectNotFound) {
			return err
		}

		if _, err := protocolPackage.PutBytes(ctx, topology.ProtocolObject(), NatsProtocolPackageBytes); err != nil {
			return err
		}

		stored, err = protocolPackage.GetBytes(ctx, topology.ProtocolObject())
		if err != nil {
			return err
		}
	}

	if !bytes.Equal(stored, NatsProtocolPackageBytes) {
		return errors.New("NATS protocol package failed its integrity check.")
	}

	startupConsumer, err := topology.StartupConsumer()
	if err != nil {
		return err
	}

	if err := natsOperationJournalCreateOrUpdateAndValidateConsumer(
		ctx, js, "CELL_EVENTS", startupConsumer); err != nil {
		return err
	}

	cellSpecConsumer, err := topology.CellSpecConsumer()
	if err != nil {
		return err
	}

	return natsOperationJournalCreateOrUpdateAndValidateConsumer(
		ctx, js, "CELL_SPEC", cellSpecConsumer)
}

func natsOperationJournalCreateOrUpdateAndValidateConsumer(
	ctx context.Context,
	js jetstream.JetStream,
	stream string,
	configuration jetstream.ConsumerConfig,
) error {
	streamHandle, err := js.Stream(ctx, stream)
	if err != nil {
		return err
	}

	consumer, err := streamHandle.CreateOrUpdateConsumer(ctx, configuration)
	if err != nil {
		return err
	}

	info, err := consumer.Info(ctx)
	if err != nil {
		return err
	}

	if !CiRunnerConsumerReconcilerMatches(info, configuration, stream) {
		return errors.New(
			"An infrastructure-provisioned NATS consumer does not match its closed profile.")
	}

	return nil
}

func natsOperationJournalOpenOrCreateObjectStore(
	ctx context.Context,
	js jetstream.JetStream,
	configuration jetstream.ObjectStoreConfig,
) (jetstream.ObjectStore, error) {
	store, err := js.ObjectStore(ctx, configuration.Bucket)
	if err == nil {
		if err := natsOperationJournalValidateObjectStore(ctx, store, configuration); err != nil {
			return nil, err
		}

		return store, nil
	}

	if !isJetStreamNotFound(err) {
		return nil, err
	}

	store, err = js.CreateObjectStore(ctx, configuration)
	if err != nil {
		return nil, err
	}

	if err := natsOperationJournalValidateObjectStore(ctx, store, configuration); err != nil {
		return nil, err
	}

	return store, nil
}

func natsOperationJournalValidateObjectStore(
	ctx context.Context,
	store jetstream.ObjectStore,
	configuration jetstream.ObjectStoreConfig,
) error {
	status, err := store.Status(ctx)
	if err != nil {
		return err
	}

	streamHandle, err := jetstreamStreamForBucket(ctx, store, configuration.Bucket)
	if err != nil {
		return err
	}

	info, err := streamHandle.Info(ctx)
	if err != nil {
		return err
	}

	_ = status

	return NatsOperationJournalStore.ValidateExactObjectConfiguration(info.Config, configuration)
}

func isJetStreamNotFound(err error) bool {
	return errors.Is(err, jetstream.ErrBucketNotFound) ||
		errors.Is(err, jetstream.ErrStreamNotFound) ||
		errors.Is(err, jetstream.ErrObjectNotFound)
}
