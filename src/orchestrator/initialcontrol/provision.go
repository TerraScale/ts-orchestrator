package initialcontrol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/journal"
	"terrascale.tech/orchestrator/src/orchestrator/control/messaging"
)

func provision(ctx context.Context, js jetstream.JetStream, p accountProfile, regional bool, cell, instance string) error {
	// Reject foreign stores before creating any missing admitted store. Never
	// update a conflicting existing stream or consumer into the expected shape.
	names := map[string]bool{}
	for _, s := range p.Streams {
		names[s.Name] = true
	}
	for _, s := range p.KV {
		names["KV_"+s.Bucket] = true
	}
	for _, s := range p.Objects {
		names["OBJ_"+s.Bucket] = true
	}
	listed := js.StreamNames(ctx)
	for name := range listed.Name() {
		if !names[name] {
			return fmt.Errorf("initial control: unexpected retained store %s", name)
		}
	}
	if err := listed.Err(); err != nil {
		return err
	}
	// Read every existing profile before any create, so conflicts fail without
	// partly provisioning a different scope.
	if err := readback(ctx, js, p, true); err != nil {
		return err
	}
	for _, s := range p.Streams {
		if _, err := js.Stream(ctx, s.Name); errors.Is(err, jetstream.ErrStreamNotFound) {
			if _, err = js.CreateStream(ctx, s); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}
	for _, s := range p.KV {
		if _, err := js.KeyValue(ctx, s.Bucket); errors.Is(err, jetstream.ErrBucketNotFound) || errors.Is(err, jetstream.ErrStreamNotFound) {
			if _, err = js.CreateKeyValue(ctx, s); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}
	for _, s := range p.Objects {
		if _, err := js.ObjectStore(ctx, s.Bucket); errors.Is(err, jetstream.ErrBucketNotFound) || errors.Is(err, jetstream.ErrStreamNotFound) {
			if _, err = js.CreateObjectStore(ctx, s); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}
	for _, c := range p.Consumers {
		stream, err := js.Stream(ctx, c.Stream)
		if err != nil {
			return err
		}
		if _, err = stream.Consumer(ctx, c.Config.Name); errors.Is(err, jetstream.ErrConsumerNotFound) {
			if _, err = stream.CreateConsumer(ctx, c.Config); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}
	if regional {
		topology := messaging.NewNatsTopology(cell, 1, instance)
		object, err := js.ObjectStore(ctx, topology.ProtocolPackage().Bucket)
		if err != nil {
			return err
		}
		value, err := object.GetBytes(ctx, topology.ProtocolObject())
		if errors.Is(err, jetstream.ErrObjectNotFound) {
			_, err = object.PutBytes(ctx, topology.ProtocolObject(), messaging.NatsProtocolPackageBytes)
			if err == nil {
				value, err = object.GetBytes(ctx, topology.ProtocolObject())
			}
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(value, messaging.NatsProtocolPackageBytes) {
			return errors.New("initial control: protocol object conflicts with admitted package")
		}
	}
	return readback(ctx, js, p, false)
}

func readback(ctx context.Context, js jetstream.JetStream, p accountProfile, allowMissing bool) error {
	check := func(name string, validate func(jetstream.StreamConfig) error) error {
		stream, err := js.Stream(ctx, name)
		if allowMissing && errors.Is(err, jetstream.ErrStreamNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		info, err := stream.Info(ctx)
		if err != nil {
			return err
		}
		if info.Config.Replicas != 1 {
			return errors.New("initial control: retained store is not R1")
		}
		if err = validate(info.Config); err != nil {
			return fmt.Errorf("initial control: profile conflict %s: %w", name, err)
		}
		return nil
	}
	for _, expected := range p.Streams {
		if err := check(expected.Name, func(actual jetstream.StreamConfig) error {
			return journal.NatsOperationJournalStore.ValidateExactStreamConfiguration(actual, expected)
		}); err != nil {
			return err
		}
	}
	for _, expected := range p.KV {
		if err := check("KV_"+expected.Bucket, func(actual jetstream.StreamConfig) error {
			return journal.NatsOperationJournalStore.ValidateExactStreamConfiguration(actual, journal.NatsOperationJournalStore.CanonicalKeyValueStream(expected))
		}); err != nil {
			return err
		}
	}
	for _, expected := range p.Objects {
		if err := check("OBJ_"+expected.Bucket, func(actual jetstream.StreamConfig) error {
			return journal.NatsOperationJournalStore.ValidateExactObjectConfiguration(actual, expected)
		}); err != nil {
			return err
		}
	}
	for _, c := range p.Consumers {
		stream, err := js.Stream(ctx, c.Stream)
		if allowMissing && errors.Is(err, jetstream.ErrStreamNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		consumer, err := stream.Consumer(ctx, c.Config.Name)
		if allowMissing && errors.Is(err, jetstream.ErrConsumerNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		info, err := consumer.Info(ctx)
		if err != nil {
			return err
		}
		if !journal.NatsConsumerProfileMatches(info, c.Config, c.Stream) {
			return fmt.Errorf("initial control: consumer profile conflict %s actual=%+v expected=%+v", c.Config.Name, info.Config, c.Config)
		}
	}
	return nil
}

func equalStrings(a, b []string) bool {
	a = append([]string(nil), a...)
	b = append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
