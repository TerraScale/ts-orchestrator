// Package serviceidentityrotation rotates dashboard introspection credentials.
// Its journal contains only provider references and public operation metadata.
package serviceidentityrotation

import (
	"context"
	"errors"
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
	Generation   uint64                              `json:"generation"`
	Active       hostsecrets.IdentitySecretReference `json:"active"`
	Pending      hostsecrets.IdentitySecretReference `json:"pending"`
	Deadline     time.Time                           `json:"deadline"`
	Phase        string                              `json:"phase"`
	NextRotation time.Time                           `json:"next_rotation"`
}

// Store must serialize updates under the live global authority lease.
type Store interface {
	Load(context.Context) (Journal, error)
	Save(context.Context, Journal) error
}
type Dashboard interface {
	SetIdentityServiceKeys(context.Context, string, []byte, []byte, time.Time) error
}

// DeliverAll succeeds only after every admitted member proves adoption.
// Revisions use 2*generation for activation and 2*generation+1 for rollback.
type Members interface {
	DeliverAll(context.Context, hostsecrets.IdentitySecretReference, uint64, []byte) error
}
type Config struct {
	Issuer          Issuer
	Store           Store
	Dashboard       Dashboard
	Members         Members
	Script          string
	Period, Overlap time.Duration
	Authority       func(context.Context) error
}
type Coordinator struct {
	config Config
	mu     sync.Mutex
}

func New(c Config) (*Coordinator, error) {
	if c.Issuer == nil || c.Store == nil || c.Dashboard == nil || c.Members == nil || c.Authority == nil || c.Script == "" || c.Period < time.Hour || c.Overlap < time.Minute || c.Overlap > 300*time.Second {
		return nil, ErrRotation
	}
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
	if err != nil {
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
	if err = c.config.Members.DeliverAll(work, j.Pending, 2*j.Generation, next.Bytes()); err != nil {
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
	if c.config.Members.DeliverAll(ctx, j.Active, 2*j.Generation+1, old.Bytes()) != nil {
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
	if c.config.Members.DeliverAll(ctx, j.Pending, 2*j.Generation, next.Bytes()) != nil {
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
