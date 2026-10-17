package journal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/nats-io/nkeys"
)

// Binding contains public identities authenticated elsewhere; it grants no rights.
type Binding struct {
	PurposeSHA256              string `json:"purposeSha256"`
	SourceSHA256               string `json:"sourceSha256"`
	GrantSHA256                string `json:"grantSha256"`
	TemplateSHA256             string `json:"templateSha256"`
	CredentialID               string `json:"credentialId"`
	CredentialSubject          string `json:"credentialSubject"`
	CredentialSHA256           string `json:"credentialSha256"`
	CurrentID                  string `json:"currentId"`
	CurrentVersion             int64  `json:"currentVersion"`
	CurrentSHA256              string `json:"currentSha256"`
	ManagerInstanceID          string `json:"managerInstanceId"`
	ManagerVNICID              string `json:"managerVnicId"`
	WriterInstanceID           string `json:"writerInstanceId"`
	WriterVNICID               string `json:"writerVnicId"`
	UnderlaySHA256             string `json:"underlaySha256"`
	ManagerAdmissionSHA256     string `json:"managerAdmissionSha256"`
	ManagerProcessSHA256       string `json:"managerProcessSha256"`
	ManagerLaunchRecipeSHA256  string `json:"managerLaunchRecipeSha256"`
	ManagerAccountIntentSHA256 string `json:"managerAccountIntentSha256,omitempty"`
	ManagerBinarySHA256        string `json:"managerBinarySha256"`
}

func (binding Binding) Validate() error {
	for _, value := range []string{binding.PurposeSHA256, binding.SourceSHA256, binding.GrantSHA256, binding.TemplateSHA256,
		binding.CredentialSHA256, binding.CurrentSHA256, binding.UnderlaySHA256, binding.ManagerAdmissionSHA256,
		binding.ManagerProcessSHA256, binding.ManagerLaunchRecipeSHA256, binding.ManagerBinarySHA256} {
		if !digest(value) {
			return ErrReservation
		}
	}
	if binding.ManagerAccountIntentSHA256 != "" && !digest(binding.ManagerAccountIntentSHA256) {
		return ErrReservation
	}
	if !publicID(binding.CredentialID) || !nkeys.IsValidPublicUserKey(binding.CredentialSubject) || binding.CurrentVersion <= 0 ||
		!nativeID(binding.CurrentID, "vaultsecret") || !nativeID(binding.ManagerInstanceID, "instance") ||
		!nativeID(binding.WriterInstanceID, "instance") || !nativeID(binding.ManagerVNICID, "vnic") || !nativeID(binding.WriterVNICID, "vnic") ||
		binding.ManagerInstanceID == binding.WriterInstanceID || binding.ManagerVNICID == binding.WriterVNICID {
		return ErrReservation
	}
	return nil
}

var ErrReservation = errors.New("invalid NetBird account reservation")

// Reservation fixes every original input before any loopback dispatch.
// A remote process binding remains signed evidence, not remote kernel observation.
type Reservation struct {
	SchemaVersion            int       `json:"schemaVersion"`
	Counter                  uint64    `json:"counter"`
	PreviousCompletionSHA256 string    `json:"previousCompletionSha256,omitempty"`
	OperationID              string    `json:"operationId"`
	Nonce                    string    `json:"nonce"`
	Binding                  Binding   `json:"binding"`
	Mutation                 Mutation  `json:"mutation"`
	StartedAt                time.Time `json:"startedAt"`
	FirstDeadline            time.Time `json:"firstDeadline"`
}

func (Reservation) String() string     { return "NetBird account reservation [redacted]" }
func (r Reservation) GoString() string { return r.String() }

func (r Reservation) Clone() Reservation {
	r.Mutation = r.Mutation.Clone()
	return r
}

func (r Reservation) Validate() error {
	if r.SchemaVersion != 1 || r.Counter == 0 || !entityid.Valid(r.OperationID) || !digest(r.Nonce) ||
		r.Counter == 1 && r.PreviousCompletionSHA256 != "" || r.Counter > 1 && !digest(r.PreviousCompletionSHA256) ||
		r.Binding.Validate() != nil || r.Mutation.Validate() != nil || r.StartedAt.IsZero() || !r.FirstDeadline.After(r.StartedAt) ||
		r.FirstDeadline.After(r.StartedAt.Add(30*time.Second)) {
		return ErrReservation
	}
	return nil
}

func (r Reservation) Digest() (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	return wireDigest(r)
}

// Completion is public response evidence; only a sealed producer can authorize it.
type Completion struct {
	ReservationSHA256 string    `json:"reservationSha256"`
	StatusCode        int       `json:"statusCode"`
	ResponseSHA256    string    `json:"responseSha256"`
	CompletedAt       time.Time `json:"completedAt"`
}

func (c Completion) Validate(reservation Reservation) error {
	fingerprint, err := reservation.Digest()
	if err != nil || c.ReservationSHA256 != fingerprint || c.StatusCode != 200 || !digest(c.ResponseSHA256) ||
		c.CompletedAt.Before(reservation.StartedAt) || !c.CompletedAt.Before(reservation.FirstDeadline) {
		return ErrReservation
	}
	return nil
}

// CompletionDigest anchors the next counter to the exact previous response.
func CompletionDigest(reservation Reservation, completion Completion) (string, error) {
	if err := completion.Validate(reservation); err != nil {
		return "", err
	}
	return wireDigest(completion)
}

// Follows permits one new operation only after the prior synchronous completion.
func (r Reservation) Follows(previous Reservation, completion Completion) error {
	fingerprint, err := CompletionDigest(previous, completion)
	if err != nil || r.Validate() != nil || previous.Counter == math.MaxUint64 || r.Counter != previous.Counter+1 ||
		r.PreviousCompletionSHA256 != fingerprint || r.OperationID == previous.OperationID || r.Nonce == previous.Nonce || r.StartedAt.Before(completion.CompletedAt) {
		return ErrReservation
	}
	return nil
}

func wireDigest(value any) (string, error) {
	wire, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		return "", ErrReservation
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:]), nil
}

func digest(value string) bool {
	wire, err := hex.DecodeString(value)
	return err == nil && len(wire) == sha256.Size && hex.EncodeToString(wire) == value
}

func publicID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_') {
			return false
		}
	}
	return true
}

func nativeID(value, kind string) bool {
	prefix := "ocid1." + kind + ".oc1.sa-saopaulo-1."
	if len(value) > 512 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for _, part := range strings.Split(strings.TrimPrefix(value, prefix), ".") {
		if len(part) == 0 {
			return false
		}
		for _, character := range part {
			if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9') {
				return false
			}
		}
	}
	return true
}
