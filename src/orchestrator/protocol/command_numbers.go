// Port of src/TerraScale.Orchestrator/Protocol/CommandNumbers.cs.
package protocol

import "strconv"

// ProtocolRevision is the positive protocol revision of a signed command.
type ProtocolRevision struct {
	Value int64
}

// IsValid reports whether the revision is a positive number.
func (r ProtocolRevision) IsValid() bool { return r.Value > 0 }

func (r ProtocolRevision) String() string { return strconv.FormatInt(r.Value, 10) }

// ProtocolRevisionTryCreate mirrors ProtocolRevision.TryCreate.
func ProtocolRevisionTryCreate(value int64) (ProtocolRevision, bool) {
	if value <= 0 {
		return ProtocolRevision{}, false
	}

	return ProtocolRevision{Value: value}, true
}

// DesiredGeneration is the positive desired generation of a signed command.
type DesiredGeneration struct {
	Value int64
}

// IsValid reports whether the generation is a positive number.
func (g DesiredGeneration) IsValid() bool { return g.Value > 0 }

func (g DesiredGeneration) String() string { return strconv.FormatInt(g.Value, 10) }

// DesiredGenerationTryCreate mirrors DesiredGeneration.TryCreate.
func DesiredGenerationTryCreate(value int64) (DesiredGeneration, bool) {
	if value <= 0 {
		return DesiredGeneration{}, false
	}

	return DesiredGeneration{Value: value}, true
}

// WriterEpoch is the positive writer epoch of a signed command.
type WriterEpoch struct {
	Value int64
}

// IsValid reports whether the epoch is a positive number.
func (e WriterEpoch) IsValid() bool { return e.Value > 0 }

func (e WriterEpoch) String() string { return strconv.FormatInt(e.Value, 10) }

// WriterEpochTryCreate mirrors WriterEpoch.TryCreate.
func WriterEpochTryCreate(value int64) (WriterEpoch, bool) {
	if value <= 0 {
		return WriterEpoch{}, false
	}

	return WriterEpoch{Value: value}, true
}

// DeliveryAttempt is the positive 1-based delivery attempt of a signed command.
type DeliveryAttempt struct {
	Value int64
}

// IsValid reports whether the attempt is a positive number.
func (a DeliveryAttempt) IsValid() bool { return a.Value > 0 }

func (a DeliveryAttempt) String() string { return strconv.FormatInt(a.Value, 10) }

// DeliveryAttemptTryCreate mirrors DeliveryAttempt.TryCreate.
func DeliveryAttemptTryCreate(value int64) (DeliveryAttempt, bool) {
	if value <= 0 {
		return DeliveryAttempt{}, false
	}

	return DeliveryAttempt{Value: value}, true
}
