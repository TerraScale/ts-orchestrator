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
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
)

var ErrInvalid = errors.New("enrollment: invalid reservation")

type Record struct {
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
	Records map[string]Record `json:"records"`
}
type transaction interface {
	Transact(context.Context, bool, func(*State) error) error
	Read(context.Context) (State, error)
}
type Journal struct{ journal transaction }

func keyFor(region string, slot int) string { return fmt.Sprintf("%s:%d", region, slot) }
func validate(s State) error {
	if len(s.Records) > 1024 {
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
		if r.Public != nil && (len(r.Public.Grant) == 0 || len(r.Public.Files) == 0 || hostsecrets.ValidateSeed(r.Public.Seed) != nil) {
			return ErrInvalid
		}
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
	if j == nil || j.journal == nil || ctx == nil || r.Region == "" || strings.TrimSpace(r.Region) != r.Region || r.Slot < 1 {
		return Record{}, ErrInvalid
	}
	err := j.journal.Transact(ctx, true, func(s *State) error {
		if prior, ok := s.Records[keyFor(r.Region, r.Slot)]; ok {
			if prior.Environment != r.Environment || prior.Cluster != r.Cluster || prior.TemplateDigest != r.TemplateDigest {
				return ErrInvalid
			}
			r = prior
			return nil
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
