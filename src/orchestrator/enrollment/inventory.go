// Package enrollment owns lease-bound member reservations and public bootstrap.
package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/oklog/ulid"
	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
)

var ErrInvalid = errors.New("enrollment: invalid reservation")

type Retirement struct {
	OperationID string `json:"operation_id"`
	ResourceID  string `json:"resource_id"`
}

type Record struct {
	Retirement        *Retirement      `json:"retirement,omitempty"`
	MemberID          string           `json:"member_id"`
	NodeID            string           `json:"node_id"`
	Environment       string           `json:"environment"`
	Cluster           string           `json:"cluster"`
	Region            string           `json:"region"`
	Slot              int              `json:"slot"`
	Generation        uint64           `json:"generation"`
	OperationID       string           `json:"operation_id"`
	TemplateDigest    string           `json:"template_digest"`
	IdentityReference string           `json:"identity_reference,omitempty"`
	IssuedAt          time.Time        `json:"issued_at"`
	ExpiresAt         time.Time        `json:"expires_at"`
	Public            *PublicBootstrap `json:"public,omitempty"`
}
type State struct {
	Retired map[string]Record `json:"retired,omitempty"`
	Records map[string]Record `json:"records"`
}
type transaction interface {
	Transact(context.Context, bool, func(*State) error) error
	Read(context.Context) (State, error)
}
type Journal struct{ journal transaction }

func keyFor(region string, slot int) string { return fmt.Sprintf("%s:%d", region, slot) }
func validate(s State) error {
	if len(s.Records) > 1024 || len(s.Retired) > 4096 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for key, r := range s.Records {
		if key != keyFor(r.Region, r.Slot) || r.Slot < 1 || r.Slot > 1024 || r.NodeID == "" || r.Environment == "" || r.Cluster == "" || r.Generation == 0 || r.OperationID == "" || r.IssuedAt.IsZero() || !r.ExpiresAt.After(r.IssuedAt) || r.ExpiresAt.Sub(r.IssuedAt) > 24*time.Hour || len(r.TemplateDigest) != 64 || seen[r.MemberID] {
			return ErrInvalid
		}
		if id, err := ulid.ParseStrict(r.MemberID); err != nil || id.String() != r.MemberID {
			return ErrInvalid
		}
		seen[r.MemberID] = true
		if r.Retirement != nil && (r.Retirement.OperationID == "" || r.Retirement.ResourceID == "") {
			return ErrInvalid
		}
		if r.Public != nil && (len(r.Public.Grant) == 0 || len(r.Public.Files) == 0 || hostsecrets.ValidateSeed(r.Public.Seed) != nil) {
			return ErrInvalid
		}
	}
	for operation, record := range s.Retired {
		if record.Retirement == nil || operation != record.Retirement.OperationID || record.Retirement.ResourceID == "" || seen[record.MemberID] {
			return ErrInvalid
		}
		if err := validate(State{Records: map[string]Record{keyFor(record.Region, record.Slot): record}}); err != nil {
			return err
		}
		seen[record.MemberID] = true
	}
	return nil
}
func NewJournal(c authorityjournal.Config) (*Journal, error) {
	c.StateKey = "member.enrollment"
	j, e := authorityjournal.New(c, func() State { return State{Records: map[string]Record{}} }, validate)
	if e != nil {
		return nil, e
	}
	return &Journal{journal: j}, nil
}

// Reserve returns an existing immutable slot before generating any new identity.
func (j *Journal) Reserve(ctx context.Context, r Record) (Record, error) {
	if j == nil || j.journal == nil || ctx == nil || r.Region == "" || strings.TrimSpace(r.Region) != r.Region || r.Slot < 1 || r.Retirement != nil {
		return Record{}, ErrInvalid
	}
	err := j.journal.Transact(ctx, true, func(s *State) error {
		if prior, ok := s.Records[keyFor(r.Region, r.Slot)]; ok {
			if prior.Environment != r.Environment || prior.Cluster != r.Cluster || prior.TemplateDigest != r.TemplateDigest {
				return ErrInvalid
			}
			if prior.Retirement == nil {
				r = prior
				return nil
			}
			if prior.Generation == ^uint64(0) || len(s.Retired) >= 4096 {
				return ErrInvalid
			}
			if s.Retired == nil {
				s.Retired = map[string]Record{}
			}
			if _, exists := s.Retired[prior.Retirement.OperationID]; exists {
				return ErrInvalid
			}
			s.Retired[prior.Retirement.OperationID] = prior
			r.Generation = max(r.Generation, prior.Generation+1)
			r.MemberID, r.OperationID, r.IdentityReference = "", "", ""
			r.Public, r.Retirement = nil, nil
		}
		if r.MemberID == "" {
			id, e := ulid.New(ulid.Timestamp(r.IssuedAt), rand.Reader)
			if e != nil {
				return e
			}
			r.MemberID = id.String()
		}
		if r.NodeID == "" {
			r.NodeID = fmt.Sprintf("%s-%d", r.Region, r.Slot)
		}
		if r.OperationID == "" {
			sum := sha256.Sum256([]byte(r.Environment + "/" + r.Cluster + "/" + r.NodeID + "/" + r.MemberID))
			r.OperationID = "enroll-" + hex.EncodeToString(sum[:20])
		}
		if e := validate(State{Records: map[string]Record{keyFor(r.Region, r.Slot): r}}); e != nil {
			return e
		}
		if s.Records == nil {
			s.Records = map[string]Record{}
		}
		s.Records[keyFor(r.Region, r.Slot)] = r
		return nil
	})
	return r, err
}

// Retire records exact completed removal evidence before Reserve may create a
// new incarnation. The runtime must first reread the exact terminal resource;
// neither an absent listing nor an OCI 404 authorizes this transition.
func (j *Journal) Retire(ctx context.Context, region string, slot int, removal hostremoval.Operation) error {
	if j == nil || j.journal == nil || ctx == nil || removal.Stage != hostremoval.StageComplete || removal.OperationID == "" || removal.ResourceID == "" {
		return ErrInvalid
	}
	return j.journal.Transact(ctx, true, func(s *State) error {
		if prior, ok := s.Retired[removal.OperationID]; ok {
			if prior.Region == region && prior.Slot == slot && prior.Retirement.ResourceID == removal.ResourceID && Identity(prior, "member") == removal.MemberIdentity && prior.Generation == removal.Generation {
				return nil
			}
			return ErrInvalid
		}
		current, ok := s.Records[keyFor(region, slot)]
		if !ok || Identity(current, "member") != removal.MemberIdentity || current.Generation != removal.Generation {
			return ErrInvalid
		}
		retirement := Retirement{OperationID: removal.OperationID, ResourceID: removal.ResourceID}
		if current.Retirement != nil && *current.Retirement != retirement {
			return ErrInvalid
		}
		current.Retirement = &retirement
		s.Records[keyFor(region, slot)] = current
		return nil
	})
}

func (j *Journal) Read(ctx context.Context) (State, error) {
	if j == nil || j.journal == nil {
		return State{}, ErrInvalid
	}
	return j.journal.Read(ctx)
}
func (j *Journal) Publish(ctx context.Context, r Record) error {
	if j == nil || j.journal == nil || r.Public == nil {
		return ErrInvalid
	}
	return j.journal.Transact(ctx, true, func(s *State) error {
		prior, ok := s.Records[keyFor(r.Region, r.Slot)]
		if !ok {
			return ErrInvalid
		}
		a, b := prior, r
		a.Public = nil
		b.Public = nil
		a.IdentityReference = ""
		b.IdentityReference = ""
		if !reflect.DeepEqual(a, b) {
			return ErrInvalid
		}
		if prior.Public != nil && !reflect.DeepEqual(prior, r) {
			return ErrInvalid
		}
		s.Records[keyFor(r.Region, r.Slot)] = r
		return validate(*s)
	})
}
func Digest(v any) (string, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
