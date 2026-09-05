// Package initialcontrol composes the owner-admitted, temporary GRU control
// plane. Its R1 profiles never change the ordinary production R3 validators.
package initialcontrol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/messaging"
)

const StorageOverheadBytes int64 = 256 << 20

type consumerProfile struct {
	Stream string
	Config jetstream.ConsumerConfig
}
type accountProfile struct {
	Streams   []jetstream.StreamConfig
	KV        []jetstream.KeyValueConfig
	Objects   []jetstream.ObjectStoreConfig
	Consumers []consumerProfile
}
type profiles struct{ Regional, Global accountProfile }

func buildProfiles(cell, instance string) (profiles, error) {
	if cell != "gru" || !messaging.GlobalNatsTopologyIsCellToken(instance) {
		return profiles{}, errors.New("initial control requires GRU and a valid instance")
	}
	regional := messaging.NewNatsTopology(cell, 1, instance)
	streams, err := regional.Streams()
	if err != nil {
		return profiles{}, err
	}
	p := profiles{Regional: accountProfile{Streams: streams, KV: []jetstream.KeyValueConfig{regional.Leaders(), regional.Runtime(), regional.Delivery(), regional.CommandReplay(), regional.Operations(), regional.OperationProofConsumptions()}, Objects: []jetstream.ObjectStoreConfig{regional.Bundles(), regional.ProtocolPackage()}}}
	// This projection is local to the signed initial profile. No ordinary
	// journal writer is constructed until the normal R3 handoff is admitted.
	for i := range p.Regional.KV {
		p.Regional.KV[i].Replicas = 1
	}
	startup, err := regional.StartupConsumer()
	if err != nil {
		return profiles{}, err
	}
	cellSpec, err := regional.CellSpecConsumer()
	if err != nil {
		return profiles{}, err
	}
	p.Regional.Consumers = []consumerProfile{{"CELL_EVENTS", startup}, {"CELL_SPEC", cellSpec}}
	global, err := messaging.NewGlobalNatsTopology(3)
	if err != nil {
		return profiles{}, err
	}
	p.Global = accountProfile{Streams: global.Streams(), KV: []jetstream.KeyValueConfig{global.Leaders(), global.Cells(), global.MasterDeliveries()}}
	for i := range p.Global.Streams {
		p.Global.Streams[i].Replicas = 1
	}
	for i := range p.Global.KV {
		p.Global.KV[i].Replicas = 1
	}
	consumer, err := global.CellSpecConsumer(cell)
	if err != nil {
		return profiles{}, err
	}
	consumer.Replicas = 1
	p.Global.Consumers = []consumerProfile{{messaging.GlobalNatsTopologyCellSpecStream, consumer}}
	return p, nil
}

// ProfileDigest binds every retained stream, KV, object store and consumer.
func ProfileDigest(cell, instance string) (string, error) {
	p, err := buildProfiles(cell, instance)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
func profileBytes(p accountProfile) int64 {
	var n int64
	for _, s := range p.Streams {
		n += s.MaxBytes
	}
	for _, s := range p.KV {
		n += s.MaxBytes
	}
	for _, s := range p.Objects {
		n += s.MaxBytes
	}
	return n
}

// RequiredStorageBytes includes both account inventories and explicit overhead.
func RequiredStorageBytes(cell, instance string) (int64, error) {
	p, err := buildProfiles(cell, instance)
	if err != nil {
		return 0, err
	}
	return profileBytes(p.Regional) + profileBytes(p.Global) + StorageOverheadBytes, nil
}
