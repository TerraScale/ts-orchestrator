// Package finalcapture captures only a sealed source copy under a finite plan.
// It composes no authority workers or customer runtime.
package finalcapture

import (
	"encoding/json/v2"
	"errors"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
)

func EnvelopeEvidence(envelope []byte, maximum int64, role, account, stream string) (controltransition.StreamEvidence, error) {
	e, err := restoredrill.InspectSnapshotEnvelope(envelope, stream, maximum)
	if err != nil {
		return controltransition.StreamEvidence{}, err
	}
	state, err := json.Marshal(e.State)
	if err != nil {
		return controltransition.StreamEvidence{}, err
	}
	result := controltransition.StreamEvidence{Role: role, Account: account, Stream: stream, Created: e.StreamCreated,
		ConfigSHA256: controltransition.Digest(e.Config), RecordsSHA256: strings.TrimPrefix(e.RecordsSHA256, "sha256:"),
		StateSHA256: controltransition.Digest(state), Consumers: []controltransition.ConsumerEvidence{}}
	for _, c := range e.Consumers {
		if c.MemoryStorage || c.Checkpoint == nil {
			return controltransition.StreamEvidence{}, errors.New("finalcapture: nonpersistent consumer cannot prove final checkpoint")
		}
		checkpoint, err := json.Marshal(c.Checkpoint)
		if err != nil {
			return controltransition.StreamEvidence{}, err
		}
		result.Consumers = append(result.Consumers, controltransition.ConsumerEvidence{Name: c.Name, Created: c.Created,
			Durable: c.Durable != "", ConfigSHA256: c.Checkpoint.ConfigSHA256, CheckpointSHA256: controltransition.Digest(checkpoint)})
	}
	return result, nil
}
