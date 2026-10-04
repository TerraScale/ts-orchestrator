package decisionlog

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"time"
)

// Version is the wire version of Decision. Readers ignore unknown fields, so
// a rolling update can add fields without a bump.
const Version = 1

// Kind names what was decided. Slices may record kinds that are not listed
// here; a kind is any short lower_snake token.
type Kind string

// Known decision kinds. Parallel slices (rollout, selfupdate, autoscale,
// storage, membership, regionplanner) use these names so the dashboard and
// the insight rules can recognise their decisions.
const (
	KindReleaseAdmitted    Kind = "release_admitted"
	KindUpgradeStarted     Kind = "upgrade_started"
	KindCanaryPromoted     Kind = "canary_promoted"
	KindBatchPromoted      Kind = "batch_promoted"
	KindRolloutCompleted   Kind = "rollout_completed"
	KindRollback           Kind = "rollback"
	KindHeld               Kind = "held"
	KindHoldCleared        Kind = "hold_cleared"
	KindFrozen             Kind = "frozen"
	KindScaleUp            Kind = "scale_up"
	KindScaleDown          Kind = "scale_down"
	KindHostLaunched       Kind = "host_launched"
	KindHostReclaimed      Kind = "host_reclaimed"
	KindMemberReplaced     Kind = "member_replaced"
	KindControllerReplaced Kind = "controller_replaced"
	KindStageChanged       Kind = "stage_changed"
	KindVolumeResized      Kind = "volume_resized"
	KindVolumeReattached   Kind = "volume_reattached"
	KindBackupTaken        Kind = "backup_taken"
	KindRegionProposed     Kind = "region_proposed"
	KindLeaderChanged      Kind = "leader_changed"
	KindQuorumDegraded     Kind = "quorum_degraded"
	KindQuorumRestored     Kind = "quorum_restored"
	KindDeliveryApplied    Kind = "delivery_applied"
	KindDeliveryHeld       Kind = "delivery_held"
	KindDeliveryRejected   Kind = "delivery_rejected"
	KindFounderLaunched    Kind = "founder_launched"
	KindPeerEnrolled       Kind = "peer_enrolled"
	// OCI declarative reconcile (internal/ociresource).
	KindOCIDesiredPublished Kind = "oci_desired_published"
	KindOCIDriftCorrected   Kind = "oci_drift_corrected"
	KindOCIResourceDeleted  Kind = "oci_resource_deleted"
	KindOCIResourceReleased Kind = "oci_resource_released"
)

// Status is where a decision's effect stands. A decision is immutable once
// recorded: a later status is a new decision whose ParentID names the first.
type Status string

const (
	StatusPending    Status = "pending"
	StatusInProgress Status = "in_progress"
	StatusSucceeded  Status = "succeeded"
	StatusFailed     Status = "failed"
	StatusRolledBack Status = "rolled_back"
)

// Terminal reports whether no later status is expected.
func (status Status) Terminal() bool {
	return status == StatusSucceeded || status == StatusFailed || status == StatusRolledBack
}

// Actor names the slice of the orchestrator that decided, on which member.
type Actor struct {
	// Slice is the deciding feature slice, for example rollout, selfupdate,
	// autoscale, placement, membership, storage, regionplanner, delivery,
	// authority, bootstrap, netbird or cluster.
	Slice string `json:"slice"`
	// Member is the deciding member's name. Journal fills it when empty.
	Member string `json:"member,omitempty"`
}

// Subject is the thing a decision is about.
type Subject struct {
	// Kind is release, service, host, volume, region, member, database,
	// seat, operation, intent, peer or cluster.
	Kind string `json:"kind"`
	ID   string `json:"id"`
	// Name is an optional human label when ID is opaque (a digest or OCID).
	Name string `json:"name,omitempty"`
}

// String renders kind/id for logs and summaries.
func (subject Subject) String() string {
	if subject.Kind == "" {
		return subject.ID
	}
	return subject.Kind + "/" + subject.ID
}

// Signal is one input that led to a decision, with the threshold it was
// compared against when there was one.
type Signal struct {
	Name string `json:"name"`
	// Value is the observed value; Text carries a non-numeric observation.
	Value float64 `json:"value,omitzero"`
	Text  string  `json:"text,omitempty"`
	Unit  string  `json:"unit,omitempty"`
	// Comparison is the operator the rule applied, for example ">=", and
	// Threshold its bound. Both are empty for a plain observation.
	Comparison string   `json:"comparison,omitempty"`
	Threshold  *float64 `json:"threshold,omitempty"`
	// Passed reports whether the signal satisfied its gate.
	Passed *bool `json:"passed,omitempty"`
}

// Alternative is an option the decider considered and did not take.
type Alternative struct {
	Option string `json:"option"`
	Reason string `json:"reason"`
}

// Decision is one journal record.
type Decision struct {
	Version int       `json:"version"`
	ID      string    `json:"id"`
	Time    time.Time `json:"time"`
	// Region is the cell (lowercase region token) the decision applies to.
	Region  string  `json:"region"`
	Actor   Actor   `json:"actor"`
	Kind    Kind    `json:"kind"`
	Subject Subject `json:"subject"`
	// Summary is one plain-language sentence of what was decided.
	Summary string `json:"summary"`
	// Reason explains why, in plain language.
	Reason string `json:"reason,omitempty"`
	// Rule names the rule or policy that fired.
	Rule         string        `json:"rule,omitempty"`
	Signals      []Signal      `json:"signals,omitempty"`
	Alternatives []Alternative `json:"alternatives,omitempty"`
	Status       Status        `json:"status"`
	// Outcome is a short result phrase, never raw upstream error text.
	Outcome string `json:"outcome,omitempty"`
	// ParentID chains this decision under an earlier one (release ->
	// canary -> batch -> complete). Related lists other linked decisions.
	ParentID string   `json:"parent_id,omitempty"`
	Related  []string `json:"related,omitempty"`
	// Epoch is the regional authority epoch the decider held, if any.
	Epoch uint64            `json:"epoch,omitzero"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

// Bounds keep one record well under the stream's message size and keep a
// careless caller from flooding the journal with megabytes of evidence.
const (
	maxTextBytes     = 512
	maxSummaryBytes  = 1024
	maxIdentityBytes = 256
	maxSignals       = 16
	maxAlternatives  = 8
	maxRelated       = 8
	maxAttrs         = 16
	// MaxRecordBytes bounds one encoded decision.
	MaxRecordBytes = 16 << 10
)

// NewID returns a new time-ordered decision ID. Callers that need to link
// children before the parent is recorded set Decision.ID to it.
func NewID() string { return newIDAt(time.Now()) }

func newIDAt(at time.Time) string {
	var random [6]byte
	_, _ = rand.Read(random[:])
	var stamp [8]byte
	binary.BigEndian.PutUint64(stamp[:], uint64(at.UnixNano()))
	return hex.EncodeToString(stamp[:]) + hex.EncodeToString(random[:])
}

// Normalize fills defaults and enforces bounds. It never fails: a record that
// is too large loses detail rather than being dropped.
func (decision Decision) Normalize(now time.Time) Decision {
	decision.Version = Version
	if decision.Time.IsZero() {
		decision.Time = now
	}
	decision.Time = decision.Time.UTC()
	if decision.ID == "" || len(decision.ID) > 64 {
		decision.ID = newIDAt(decision.Time)
	}
	if decision.Status == "" {
		decision.Status = StatusSucceeded
	}
	decision.Region = strings.ToLower(clip(decision.Region, 64))
	decision.Kind = Kind(clip(string(decision.Kind), 64))
	decision.Actor.Slice = clip(decision.Actor.Slice, 64)
	decision.Actor.Member = clip(decision.Actor.Member, maxIdentityBytes)
	decision.Subject.Kind = clip(decision.Subject.Kind, 64)
	decision.Subject.ID = clip(decision.Subject.ID, maxIdentityBytes)
	decision.Subject.Name = clip(decision.Subject.Name, maxIdentityBytes)
	decision.Summary = clip(decision.Summary, maxSummaryBytes)
	decision.Reason = clip(decision.Reason, maxSummaryBytes)
	decision.Rule = clip(decision.Rule, maxTextBytes)
	decision.Outcome = clip(decision.Outcome, maxTextBytes)
	decision.ParentID = clip(decision.ParentID, 64)
	if len(decision.Signals) > maxSignals {
		decision.Signals = decision.Signals[:maxSignals]
	}
	decision.Signals = slices.Clone(decision.Signals)
	for index := range decision.Signals {
		signal := &decision.Signals[index]
		signal.Name = clip(signal.Name, 128)
		signal.Text = clip(signal.Text, maxTextBytes)
		signal.Unit = clip(signal.Unit, 32)
		signal.Comparison = clip(signal.Comparison, 8)
	}
	if len(decision.Alternatives) > maxAlternatives {
		decision.Alternatives = decision.Alternatives[:maxAlternatives]
	}
	decision.Alternatives = slices.Clone(decision.Alternatives)
	for index := range decision.Alternatives {
		decision.Alternatives[index].Option = clip(decision.Alternatives[index].Option, maxTextBytes)
		decision.Alternatives[index].Reason = clip(decision.Alternatives[index].Reason, maxTextBytes)
	}
	if len(decision.Related) > maxRelated {
		decision.Related = decision.Related[:maxRelated]
	}
	decision.Related = slices.Clone(decision.Related)
	for index := range decision.Related {
		decision.Related[index] = clip(decision.Related[index], 64)
	}
	if len(decision.Attrs) > 0 {
		attrs := make(map[string]string, min(len(decision.Attrs), maxAttrs))
		for _, key := range slices.Sorted(maps.Keys(decision.Attrs)) {
			if len(attrs) == maxAttrs {
				break
			}
			attrs[clip(key, 64)] = clip(decision.Attrs[key], maxTextBytes)
		}
		decision.Attrs = attrs
	}
	return fit(decision)
}

// fit sheds optional evidence until the encoded record is within
// MaxRecordBytes, so the durable copy is never refused for its size: the
// per-field bounds alone allow more than that once JSON escaping is
// counted. Attributes go first, then alternatives, related IDs and signals
// (newest listed last, dropped first), then the free text is shortened.
func fit(decision Decision) Decision {
	size := func() int {
		data, err := json.Marshal(decision)
		if err != nil {
			return 0
		}
		return len(data)
	}
	for size() > MaxRecordBytes {
		switch {
		case len(decision.Attrs) > 0:
			keys := slices.Sorted(maps.Keys(decision.Attrs))
			delete(decision.Attrs, keys[len(keys)-1])
		case len(decision.Alternatives) > 0:
			decision.Alternatives = decision.Alternatives[:len(decision.Alternatives)-1]
		case len(decision.Related) > 0:
			decision.Related = decision.Related[:len(decision.Related)-1]
		case len(decision.Signals) > 0:
			decision.Signals = decision.Signals[:len(decision.Signals)-1]
		case len(decision.Outcome) > 0:
			decision.Outcome = ""
		case len(decision.Reason) > maxTextBytes/4:
			decision.Reason = clip(decision.Reason, len(decision.Reason)/2)
		case len(decision.Summary) > maxTextBytes/4:
			decision.Summary = clip(decision.Summary, len(decision.Summary)/2)
		default:
			return decision
		}
	}
	return decision
}

// Root reports whether the decision starts a chain.
func (decision Decision) Root() bool { return decision.ParentID == "" }

func clip(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	cut := limit
	for cut > 0 && !utf8Start(value[cut]) {
		cut--
	}
	return value[:cut]
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// Threshold returns a pointer for Signal.Threshold.
func Threshold(value float64) *float64 { return &value }

// Passed returns a pointer for Signal.Passed.
func Passed(value bool) *bool { return &value }
