// Package regionlink is the read-only cross-region request path the
// dashboard providers use to ask other regional cells for telemetry.
//
// Each region is its own NATS cell with its own operator, so there is no
// shared NATS fabric yet. Links holds one connection per reachable region:
// today only the local cell's own connection, and later a connection per
// multi-region link (gateway, leafnode or a dedicated read-only client) once
// that slice lands. A configured region without a connection is reported as
// not linked rather than unreachable, so the dashboard can tell "we cannot
// see it yet" apart from "it stopped answering".
//
// Requests go to ts.orch.v1.<region>.obs.<leaf> subjects built with
// internal/protocol. They carry read-only queries and never drive a
// mutation.
package regionlink

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// DefaultTimeout bounds one cross-region request.
const DefaultTimeout = 2 * time.Second

var (
	// ErrNotLinked reports a configured region without a connection.
	ErrNotLinked = errors.New("region is not linked")
	// ErrUnknownRegion reports a region that is not configured.
	ErrUnknownRegion = errors.New("region is not configured")
)

// Requester is the narrow interface the providers depend on. Links
// implements it; tests substitute a fake.
type Requester interface {
	// Local is this member's region token (lowercase cell name).
	Local() string
	// Regions lists every configured region, local first, then sorted.
	Regions() []string
	// Linked reports whether region has a connection.
	Linked(region string) bool
	// Request sends payload to the region's observability leaf and returns
	// the reply. It returns ErrNotLinked for a configured region without a
	// connection.
	Request(ctx context.Context, region, leaf string, payload []byte) ([]byte, error)
}

// Links is the set of regional connections of one member.
type Links struct {
	local   string
	timeout time.Duration
	mu      sync.RWMutex
	regions []string
	conns   map[string]*nats.Conn
}

// New returns links for the local region over its own cell connection.
// configured lists every product region (any case); the local region is
// always included. A nil conn leaves the local region unlinked.
func New(local string, conn *nats.Conn, configured []string, timeout time.Duration) (*Links, error) {
	token, err := protocol.RegionToken(local)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	links := &Links{local: token, timeout: timeout, conns: map[string]*nats.Conn{}}
	links.regions = append(links.regions, token)
	for _, region := range configured {
		if regionToken, err := protocol.RegionToken(region); err == nil && regionToken != protocol.GlobalScope &&
			!slices.Contains(links.regions, regionToken) {
			links.regions = append(links.regions, regionToken)
		}
	}
	slices.Sort(links.regions[1:])
	if conn != nil {
		links.conns[token] = conn
	}
	return links, nil
}

// Link attaches (or with a nil conn, detaches) a region's connection. An
// unconfigured region is added to the configured set.
func (links *Links) Link(region string, conn *nats.Conn) error {
	token, err := protocol.RegionToken(region)
	if err != nil || token == protocol.GlobalScope {
		return protocol.ErrInvalidSubjectToken
	}
	links.mu.Lock()
	defer links.mu.Unlock()
	if !slices.Contains(links.regions, token) {
		links.regions = append(links.regions, token)
		slices.Sort(links.regions[1:])
	}
	if conn == nil {
		delete(links.conns, token)
	} else {
		links.conns[token] = conn
	}
	return nil
}

// Local returns this member's region token.
func (links *Links) Local() string { return links.local }

// Regions returns every configured region, local first.
func (links *Links) Regions() []string {
	links.mu.RLock()
	defer links.mu.RUnlock()
	return slices.Clone(links.regions)
}

// Linked reports whether region has a connection.
func (links *Links) Linked(region string) bool {
	links.mu.RLock()
	defer links.mu.RUnlock()
	_, ok := links.conns[strings.ToLower(region)]
	return ok
}

// Request sends one read-only request to region's observability leaf.
func (links *Links) Request(ctx context.Context, region, leaf string, payload []byte) ([]byte, error) {
	region = strings.ToLower(region)
	links.mu.RLock()
	conn, linked := links.conns[region]
	configured := slices.Contains(links.regions, region)
	links.mu.RUnlock()
	if !configured {
		return nil, ErrUnknownRegion
	}
	if !linked {
		return nil, ErrNotLinked
	}
	subject, err := protocol.ObservabilitySubject(region, leaf)
	if err != nil {
		return nil, err
	}
	// Always bound the request by the link timeout; an earlier caller
	// deadline still wins, a later one does not stretch it.
	ctx, cancel := context.WithTimeout(ctx, links.timeout)
	defer cancel()
	message, err := conn.RequestWithContext(ctx, subject, payload)
	if err != nil {
		return nil, err
	}
	return message.Data, nil
}

// Static is a fixed Requester for tests and single-region processes.
type Static struct {
	LocalRegion string
	All         []string
	Handler     func(ctx context.Context, region, leaf string, payload []byte) ([]byte, error)
}

// Local returns the local region.
func (static Static) Local() string { return static.LocalRegion }

// Regions returns All, or just the local region.
func (static Static) Regions() []string {
	if len(static.All) == 0 {
		return []string{static.LocalRegion}
	}
	return slices.Clone(static.All)
}

// Linked reports whether a handler exists.
func (static Static) Linked(string) bool { return static.Handler != nil }

// Request calls Handler, or reports the region as not linked.
func (static Static) Request(ctx context.Context, region, leaf string, payload []byte) ([]byte, error) {
	if static.Handler == nil {
		return nil, ErrNotLinked
	}
	return static.Handler(ctx, region, leaf, payload)
}

var (
	_ Requester = (*Links)(nil)
	_ Requester = Static{}
)
