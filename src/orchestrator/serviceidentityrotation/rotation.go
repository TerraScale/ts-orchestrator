// Package serviceidentityrotation rotates dashboard introspection credentials.
// Its journal contains only provider references and public operation metadata.
package serviceidentityrotation

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
	"time"
)

var ErrRotation = errors.New("identity service rotation unavailable")

type Issuer interface {
	Generate(context.Context, hostsecrets.IdentitySecretRequest) (hostsecrets.IdentitySecretReference, error)
	Fetch(context.Context, hostsecrets.IdentitySecretReference) (*hostsecrets.IdentitySecret, error)
}
type Journal struct {
	Members        []RemoteMemberEndpoint              `json:"members"`
	RosterRevision uint64                              `json:"roster_revision"`
	Generation     uint64                              `json:"generation"`
	Active         hostsecrets.IdentitySecretReference `json:"active"`
	Pending        hostsecrets.IdentitySecretReference `json:"pending"`
	Deadline       time.Time                           `json:"deadline"`
	Phase          string                              `json:"phase"`
	NextRotation   time.Time                           `json:"next_rotation"`
}

// Store must serialize updates under the live global authority lease.
type Store interface {
	Load(context.Context) (Journal, error)
	Save(context.Context, Journal) error
}
type Dashboard interface {
	SetIdentityServiceKeys(context.Context, string, []byte, []byte, time.Time) error
}

// DeliverTo succeeds only after every admitted member proves adoption.
// Revisions use 2*generation for activation and 2*generation+1 for rollback.
type Members interface {
	ValidateEnrollment(context.Context, RemoteMemberEndpoint) error
	DeliverTo(context.Context, []RemoteMemberEndpoint, hostsecrets.IdentitySecretReference, uint64, []byte) error
}
type Config struct {
	BootstrapMembers []RemoteMemberEndpoint
	Issuer           Issuer
	Store            Store
	Dashboard        Dashboard
	Members          Members
	Script           string
	Period, Overlap  time.Duration
	Authority        func(context.Context) error
}
type Coordinator struct {
	config Config
	mu     sync.Mutex
}

func New(c Config) (*Coordinator, error) {
	if c.Issuer == nil || c.Store == nil || c.Dashboard == nil || c.Members == nil || c.Authority == nil || c.Script == "" || c.Period < time.Hour || c.Overlap < time.Minute || c.Overlap > 300*time.Second {
		return nil, ErrRotation
	}
	if !validRoster(c.BootstrapMembers) {
		return nil, ErrRotation
	}
	c.BootstrapMembers = slices.Clone(c.BootstrapMembers)
	return &Coordinator{config: c}, nil
}
func (c *Coordinator) Close() error { return nil }

// Run recovers the persisted operation on every invocation. The deadline is
// persisted before any external change and is never extended on retries.
func (c *Coordinator) Run(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.config.Authority(ctx) != nil {
		return ErrRotation
	}
	j, err := c.config.Store.Load(ctx)
	if err != nil || !validJournal(j) {
		return ErrRotation
	}
	if j.Active.SecretID == "" {
		return c.bootstrap(ctx, j)
	}
	if j.Phase == "" && time.Now().Before(j.NextRotation) {
		return nil
	}
	if j.Phase == "" {
		if j.Generation >= 1<<63-1 {
			return ErrRotation
		}
		j.Generation++
		j.Phase = "issue"
		j.Deadline = time.Now().Add(c.config.Overlap).Truncate(time.Second)
		if c.config.Store.Save(ctx, j) != nil {
			return ErrRotation
		}
	}
	// Keep a recovery budget before verifier expiry, including provider calls.
	if j.Phase == "commit" {
		return c.commit(ctx, j)
	}
	if j.Phase == "rollback" || !time.Now().Before(j.Deadline.Add(-30*time.Second)) {
		return c.rollback(ctx, j)
	}
	if j.Phase == "issue" {
		j.Pending, err = c.config.Issuer.Generate(ctx, hostsecrets.IdentitySecretRequest{OperationID: j.Deadline.UTC().Format("20060102T150405Z"), Generation: j.Generation})
		if err != nil {
			return ErrRotation
		}
		j.Phase = "stage"
		if c.config.Store.Save(ctx, j) != nil {
			return ErrRotation
		}
	}
	old, err := c.config.Issuer.Fetch(ctx, j.Active)
	if err != nil {
		return ErrRotation
	}
	defer old.Close()
	next, err := c.config.Issuer.Fetch(ctx, j.Pending)
	if err != nil {
		return ErrRotation
	}
	defer next.Close()
	work, cancel := context.WithDeadline(ctx, j.Deadline.Add(-30*time.Second))
	defer cancel()
	if c.config.Authority(work) != nil {
		return ErrRotation
	}
	if err = c.config.Dashboard.SetIdentityServiceKeys(work, c.config.Script, next.Bytes(), old.Bytes(), j.Deadline); err != nil {
		return ErrRotation
	}
	if c.config.Authority(work) != nil {
		return ErrRotation
	}
	if err = c.config.Members.DeliverTo(work, slices.Clone(j.Members), j.Pending, 2*j.Generation, next.Bytes()); err != nil {
		return c.rollback(ctx, j)
	}
	j.Phase = "commit"
	if c.config.Store.Save(work, j) != nil {
		return ErrRotation
	}
	return c.commit(work, j)
}
func (c *Coordinator) commit(ctx context.Context, j Journal) error {
	next, err := c.config.Issuer.Fetch(ctx, j.Pending)
	if err != nil {
		return ErrRotation
	}
	defer next.Close()
	if c.config.Authority(ctx) != nil {
		return ErrRotation
	}
	if c.config.Dashboard.SetIdentityServiceKeys(ctx, c.config.Script, next.Bytes(), nil, time.Time{}) != nil {
		return ErrRotation
	}
	j.Active = j.Pending
	j.Pending = hostsecrets.IdentitySecretReference{}
	j.Phase = ""
	j.Deadline = time.Time{}
	j.NextRotation = time.Now().Add(c.config.Period)
	if c.config.Store.Save(ctx, j) != nil {
		return ErrRotation
	}
	return nil
}

func (c *Coordinator) rollback(ctx context.Context, j Journal) error {
	if c.config.Authority(ctx) != nil {
		return ErrRotation
	}
	j.Phase = "rollback"
	if c.config.Store.Save(ctx, j) != nil {
		return ErrRotation
	}
	old, err := c.config.Issuer.Fetch(ctx, j.Active)
	if err != nil {
		return ErrRotation
	}
	defer old.Close()
	// Restore dashboard first so stalled members keep using the durable baseline.
	if c.config.Dashboard.SetIdentityServiceKeys(ctx, c.config.Script, old.Bytes(), nil, time.Time{}) != nil {
		return ErrRotation
	}
	if c.config.Authority(ctx) != nil {
		return ErrRotation
	}
	if c.config.Members.DeliverTo(ctx, slices.Clone(j.Members), j.Active, 2*j.Generation+1, old.Bytes()) != nil {
		return ErrRotation
	}
	j.Pending = hostsecrets.IdentitySecretReference{}
	j.Phase = ""
	j.Deadline = time.Time{}
	j.NextRotation = time.Now().Add(c.config.Period)
	if c.config.Store.Save(ctx, j) != nil {
		return ErrRotation
	}
	return nil
}

// Bootstrap issues the first durable provider secret before admitting consumers.
func (c *Coordinator) bootstrap(ctx context.Context, j Journal) error {
	if j.Phase == "" {
		j.Members = slices.Clone(c.config.BootstrapMembers)
		j.RosterRevision = 1
		j.Generation = 1
		j.Phase = "bootstrap"
		j.Deadline = time.Now().UTC().Truncate(time.Second)
		if c.config.Store.Save(ctx, j) != nil {
			return ErrRotation
		}
	}
	if j.Phase != "bootstrap" {
		return ErrRotation
	}
	var err error
	if j.Pending.SecretID == "" {
		j.Pending, err = c.config.Issuer.Generate(ctx, hostsecrets.IdentitySecretRequest{OperationID: "bootstrap-" + j.Deadline.Format("20060102T150405Z"), Generation: j.Generation})
		if err != nil {
			return ErrRotation
		}
		if c.config.Store.Save(ctx, j) != nil {
			return ErrRotation
		}
	}
	next, err := c.config.Issuer.Fetch(ctx, j.Pending)
	if err != nil {
		return ErrRotation
	}
	defer next.Close()
	if c.config.Authority(ctx) != nil {
		return ErrRotation
	}
	if c.config.Dashboard.SetIdentityServiceKeys(ctx, c.config.Script, next.Bytes(), nil, time.Time{}) != nil {
		return ErrRotation
	}
	if c.config.Authority(ctx) != nil {
		return ErrRotation
	}
	if c.config.Members.DeliverTo(ctx, slices.Clone(j.Members), j.Pending, 2*j.Generation, next.Bytes()) != nil {
		return ErrRotation
	}
	j.Active = j.Pending
	j.Pending = hostsecrets.IdentitySecretReference{}
	j.Phase = ""
	j.Deadline = time.Time{}
	j.NextRotation = time.Now().Add(c.config.Period)
	if c.config.Store.Save(ctx, j) != nil {
		return ErrRotation
	}
	return nil
}

func validRoster(members []RemoteMemberEndpoint) bool { return validJournalRoster(members) }

// Enroll must succeed before a newly provisioned host becomes admitted-ready.
// Persisting the roster first ensures a failed delivery remains in every later
// rotation; retrying the same endpoint proves adoption again before success.
func (c *Coordinator) Enroll(ctx context.Context, member RemoteMemberEndpoint) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !validRoster([]RemoteMemberEndpoint{member}) || c.config.Authority(ctx) != nil {
		return ErrRotation
	}
	j, err := c.config.Store.Load(ctx)
	if err != nil || !validJournal(j) || j.Phase != "" || j.Active.SecretID == "" || j.Generation >= 1<<63-1 {
		return ErrRotation
	}
	found := false
	for _, existing := range j.Members {
		if existing.NodeID == member.NodeID {
			if existing != member {
				return ErrRotation
			}
			found = true
		} else if strings.TrimSuffix(existing.URL, "/") == strings.TrimSuffix(member.URL, "/") {
			return ErrRotation
		}
	}
	if !found {
		if c.config.Members.ValidateEnrollment(ctx, member) != nil {
			return ErrRotation
		}
		if j.RosterRevision == ^uint64(0) {
			return ErrRotation
		}
		j.Members = append(slices.Clone(j.Members), member)
		if !validRoster(j.Members) {
			return ErrRotation
		}
		j.RosterRevision++
		if c.config.Store.Save(ctx, j) != nil {
			return ErrRotation
		}
	}
	active, err := c.config.Issuer.Fetch(ctx, j.Active)
	if err != nil {
		return ErrRotation
	}
	defer active.Close()
	if c.config.Authority(ctx) != nil {
		return ErrRotation
	}
	if c.config.Members.DeliverTo(ctx, slices.Clone(j.Members), j.Active, 2*j.Generation+1, active.Bytes()) != nil {
		return ErrRotation
	}
	if c.config.Authority(ctx) != nil {
		return ErrRotation
	}
	return nil
}

// RetireMember removes an already fenced and withdrawn host from future
// deliveries. The admission owner must withdraw the host before calling it.
func (c *Coordinator) RetireMember(ctx context.Context, member RemoteMemberEndpoint) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.config.Authority(ctx) != nil {
		return ErrRotation
	}
	j, err := c.config.Store.Load(ctx)
	if err != nil || !validJournal(j) || j.Phase != "" || j.Active.SecretID == "" || len(j.Members) <= 1 || j.RosterRevision == ^uint64(0) {
		return ErrRotation
	}
	index := slices.Index(j.Members, member)
	if index < 0 {
		return ErrRotation
	}
	j.Members = slices.Delete(slices.Clone(j.Members), index, index+1)
	j.RosterRevision++
	if c.config.Store.Save(ctx, j) != nil {
		return ErrRotation
	}
	return nil
}
