package edge

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const urgentCertificateMargin = 14 * 24 * time.Hour

type certificateHolding struct {
	Expiry       time.Time
	HealthyUntil time.Time
	Fingerprint  string
}

type certificateHoldings struct {
	Version      string
	Registered   []string
	Certificates map[string]certificateHolding
}

func (c *certificateCache) publishHoldings(ctx context.Context) error {
	c.inventoryMu.Lock()
	defer c.inventoryMu.Unlock()
	if err := c.open(ctx); err != nil {
		return err
	}
	var result error
	c.pending.Range(func(key, _ any) bool {
		lock := c.variantLock(key.(string))
		lock.Lock()
		result = errors.Join(result, c.publishRetry(ctx, key.(string)))
		lock.Unlock()
		return ctx.Err() == nil
	})
	if result != nil {
		return result
	}
	self, registered, err := c.roster()
	if err != nil {
		return err
	}
	holdings := certificateHoldings{Version: "v1", Registered: registered, Certificates: map[string]certificateHolding{}}
	c.memory.Range(func(key, value any) bool {
		candidate := value.(cachedCertificate)
		until := candidate.cert.Leaf.NotAfter
		window := min(30*24*time.Hour, until.Sub(candidate.cert.Leaf.NotBefore)/3)
		holdings.Certificates[key.(string)] = certificateHolding{until, until.Add(-window), certificateFingerprint(candidate.cert)}
		if err := c.reconcile(ctx, key.(string)); err != nil && !errors.Is(err, errUnsupportedCertificate) {
			result = errors.Join(result, err)
		}
		return ctx.Err() == nil
	})
	if result != nil {
		return result
	}
	c.mu.Lock()
	certs := c.certs
	c.mu.Unlock()
	bucketKey := "holdings." + cacheKey(self)
	old, err := storeCall(ctx, func(ctx context.Context) ([]byte, error) {
		entry, err := certs.Get(ctx, bucketKey)
		if err != nil {
			return nil, err
		}
		return entry.Value(), nil
	})
	if err == nil {
		var previous certificateHoldings
		if json.Unmarshal(old, &previous) != nil || previous.Version != "v1" {
			return errUnsupportedCertificate
		}
		holdings.Registered = append(holdings.Registered, previous.Registered...)
	} else if !errors.Is(err, jetstream.ErrKeyNotFound) {
		return err
	}
	slices.Sort(holdings.Registered)
	holdings.Registered = slices.Compact(holdings.Registered)
	data, err := json.Marshal(holdings)
	if err != nil {
		return err
	}
	_, err = storeCall(ctx, func(ctx context.Context) (uint64, error) { return certs.Put(ctx, bucketKey, data) })
	return err
}

func (c *certificateCache) orderEvidence(ctx context.Context, key string) error {
	name, _ := certificateVariant(key)
	for _, serving := range []string{name, name + "+rsa"} {
		if local, ok := c.memory.Load(serving); ok && time.Until(local.(cachedCertificate).cert.Leaf.NotAfter) <= urgentCertificateMargin {
			return nil
		}
	}
	_, registered, err := c.roster()
	if err != nil {
		return err
	}
	c.mu.Lock()
	reader := c.reader
	c.mu.Unlock()
	seen := map[string]bool{}
	for len(registered) > 0 {
		node := registered[0]
		registered = registered[1:]
		if seen[node] {
			continue
		}
		seen[node] = true
		entry, err := storeCall(ctx, func(ctx context.Context) (*nats.RawStreamMsg, error) {
			return reader.GetLastMsg("KV_edge-certs", "$KV.edge-certs.holdings."+cacheKey(node), nats.Context(ctx))
		})
		if err != nil {
			return c.deferRenewal(key, "peer inventory unavailable", "peer", node, "error", err)
		}
		var holdings certificateHoldings
		if entry.Header.Get("KV-Operation") != "" || json.Unmarshal(entry.Data, &holdings) != nil || holdings.Version != "v1" {
			return c.deferRenewal(key, "peer inventory unsupported", "peer", node)
		}
		if cert, ok := holdings.Certificates[key]; ok && time.Now().Before(cert.HealthyUntil) {
			return c.deferRenewal(key, "peer holds a healthy certificate", "peer", node, "healthy_until", stamp(cert.HealthyUntil))
		}
		registered = append(registered, holdings.Registered...)
	}
	if len(seen) == 0 {
		return c.deferRenewal(key, "certificate roster empty")
	}
	return nil
}
