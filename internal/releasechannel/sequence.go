package releasechannel

import (
	"context"
	"encoding/hex"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// SequenceMigrationObject is immutable metadata addressed by the fingerprint
// carried in the authenticated release record.
func SequenceMigrationObject(fingerprint string) string {
	return "releases/sequence-migrations/" + fingerprint + ".json"
}

func ReadSequenceMigration(ctx context.Context, location Location, fingerprint string) (trust.Envelope, bool, error) {
	if _, err := hex.DecodeString(fingerprint); err != nil || len(fingerprint) != 64 || strings.ToLower(fingerprint) != fingerprint {
		return trust.Envelope{}, false, fmt.Errorf("%w: migration fingerprint", ErrInvalid)
	}
	wire, _, found, err := location.get(ctx, SequenceMigrationObject(fingerprint), trust.MaxEnvelopeBytes)
	if err != nil || !found {
		return trust.Envelope{}, found, err
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return trust.Envelope{}, true, err
	}
	digest, err := trust.Fingerprint(envelope)
	if err != nil {
		return trust.Envelope{}, true, err
	}
	if digest != fingerprint {
		return trust.Envelope{}, true, fmt.Errorf("%w: migration fingerprint", ErrInvalid)
	}
	return envelope, true, nil
}

func compareChannelOrder(existing, next Channel) error {
	switch {
	case existing.ReleaseSequence > 0:
		if next.ReleaseSequence < existing.ReleaseSequence {
			return ErrStale
		}
		if next.ReleaseSequence == existing.ReleaseSequence && (next.SourceRevision != existing.SourceRevision || next.RunNumber != existing.RunNumber) {
			return fmt.Errorf("%w: sequence already names another release", ErrInvalid)
		}
		if next.ReleaseSequence == existing.ReleaseSequence {
			previous, err := channelBinaryIdentities(existing)
			if err != nil {
				return err
			}
			incoming, err := channelBinaryIdentities(next)
			if err != nil {
				return err
			}
			if !maps.Equal(previous, incoming) {
				return fmt.Errorf("%w: sequence already names another artifact", ErrInvalid)
			}
		}
	case next.ReleaseSequence > 0:
		envelope, err := trust.DecodeEnvelope(next.SequenceMigration)
		if err != nil {
			return err
		}
		// Publish receives an already verified channel; the root signature is
		// checked by Channel.Verify at the admission boundary.
		var migration release.SequenceMigration
		if err := protocol.DecodeStrict(envelope.Payload, &migration, trust.MaxPayloadBytes); err != nil {
			return err
		}
		if err := migration.Validate(); err != nil {
			return err
		}
		if migration.Role != "orchestrator" || migration.Environment != next.Environment || next.ReleaseSequence <= migration.SequenceFloor || !migration.AdmitsLegacyFloor(next.Cell, existing.RunNumber, time.Time{}) {
			return fmt.Errorf("%w: migration does not cover retained channel floor", ErrStale)
		}
	default:
		if existing.RunNumber > next.RunNumber {
			return ErrStale
		}
		if existing.RunNumber == next.RunNumber && existing.SourceRevision != next.SourceRevision {
			return fmt.Errorf("%w: run already names another release", ErrInvalid)
		}
	}
	return nil
}

func channelBinaryIdentities(channel Channel) (map[string]release.BinaryReceipt, error) {
	binaries := make(map[string]release.BinaryReceipt, len(channel.Receipts))
	for _, wire := range channel.Receipts {
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil {
			return nil, err
		}
		var receipt release.BinaryUpdateReceipt
		if err := protocol.DecodeStrict(envelope.Payload, &receipt, trust.MaxPayloadBytes); err != nil {
			return nil, err
		}
		if _, found := binaries[receipt.Binary.GOARCH]; found {
			return nil, fmt.Errorf("%w: duplicate binary architecture", ErrInvalid)
		}
		binaries[receipt.Binary.GOARCH] = receipt.Binary
	}
	return binaries, nil
}
