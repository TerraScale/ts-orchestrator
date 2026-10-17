package hostenroll

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/nats-io/nats.go/jetstream"
)

// OpenWorkerMembershipReader opens the existing enrollment source without
// creating or updating its stream. Observation queries carry no new admission.
func OpenWorkerMembershipReader(ctx context.Context, mutations *authority.Reader, hosts *host.Reader, js jetstream.JetStream, cell string, public ed25519.PublicKey) (*WorkerMembershipSource, error) {
	if js == nil {
		return nil, errors.New("worker membership requires the current enrollment stream")
	}
	kv, err := js.KeyValue(ctx, GrantBucket)
	if err != nil {
		return nil, err
	}
	return NewWorkerMembershipSource(ctx, mutations, hosts, &GrantStore{kv: kv, js: js}, js, cell, public)
}
