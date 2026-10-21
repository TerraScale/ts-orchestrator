package runtimecostsnapshot

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/controlaccess"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// Client consumes runtime-resolved regional access; it has no URL or token
// configuration of its own. HTTP is a caller-owned transport for integration.
type Client struct {
	Access controlaccess.Access
	HTTP   *http.Client
}

// Read selects a complete admitted controller answer, or the newest available
// partial observation. Failure never infers a price or discards a pending view.
func (c Client) Read(ctx context.Context, region string) (Snapshot, error) {
	region = strings.ToLower(region)
	if _, ok := catalog.Lookup(strings.ToUpper(region)); !ok {
		return Snapshot{}, errors.New("cost region is outside the catalog")
	}
	if len(c.Access.URLs) == 0 || len(c.Access.URLs) > 64 || len(c.Access.Token) < 32 || len(c.Access.Token) > 4096 {
		return Snapshot{}, errors.New("cost requires admitted regional read access")
	}
	for _, b := range []byte(c.Access.Token) {
		if b <= ' ' || b >= 127 {
			return Snapshot{}, errors.New("cost requires a valid bearer token")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	var pending sync.WaitGroup
	defer func() { cancel(); pending.Wait() }()
	hc := http.Client{}
	if c.HTTP != nil {
		hc = *c.HTTP
	} else {
		transport := &http.Transport{Proxy: nil, IdleConnTimeout: 30 * time.Second}
		defer transport.CloseIdleConnections()
		hc.Transport = transport
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	requests := make([]*http.Request, 0, len(c.Access.URLs))
	for _, origin := range c.Access.URLs {
		u, err := url.Parse(origin)
		if err != nil || len(origin) > 2048 || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || u.Path != "" && u.Path != "/" || strings.ContainsAny(origin, "\r\n\t ") {
			return Snapshot{}, errors.New("invalid cost origin")
		}
		if u.Scheme != "https" {
			address, err := netip.ParseAddr(u.Hostname())
			if u.Scheme != "http" || err != nil || !address.IsLoopback() {
				return Snapshot{}, errors.New("cost origin requires HTTPS")
			}
		}
		u.Path = Path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return Snapshot{}, errors.New("invalid cost request")
		}
		req.Header.Set("Authorization", "Bearer "+c.Access.Token)
		requests = append(requests, req)
	}
	results := make(chan *Snapshot, len(requests))
	for _, req := range requests {
		pending.Go(func() {
			var result *Snapshot
			defer func() { results <- result }()
			response, err := hc.Do(req)
			if err != nil {
				return
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				return
			}
			wire, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
			if err != nil || len(wire) > 8<<20 {
				return
			}
			var snapshot Snapshot
			if json.Unmarshal(wire, &snapshot) != nil {
				return
			}
			if err := snapshot.validate(region); err == nil || errors.Is(err, ErrPending) {
				result = &snapshot
			}
		})
	}
	var best *Snapshot
	for range requests {
		select {
		case <-ctx.Done():
			if best != nil {
				return *best, errors.Join(ErrPending, ctx.Err())
			}
			return Snapshot{}, ctx.Err()
		case result := <-results:
			if err := ctx.Err(); err != nil {
				if best != nil {
					return *best, errors.Join(ErrPending, err)
				}
				return Snapshot{}, err
			}
			if result == nil {
				continue
			}
			if result.validate(region) == nil {
				return *result, nil
			}
			if best == nil || result.ObservedAt.After(best.ObservedAt) {
				best = result
			}
		}
	}
	if best != nil {
		return *best, ErrPending
	}
	return Snapshot{}, errors.New("no regional controller returned a valid cost snapshot")
}
