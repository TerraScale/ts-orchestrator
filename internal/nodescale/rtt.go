package nodescale

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"regexp"
	"slices"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

const (
	RTTInterval = 10 * time.Minute
	RTTTimeout  = 3 * time.Second
	RTTSamples  = 3 // connects per region per round; the median counts

	rttWorkers = 8 // regions probed at once
)

// ociRegionName is an OCI region's name, such as "us-sanjose-1". Only names that match are dialed.
var ociRegionName = regexp.MustCompile(`^[a-z]+-[a-z]+-[0-9]+$`)

// Prober measures TCP connect time to OCI regions' object storage endpoints.
type Prober struct {
	Regions func(ctx context.Context) ([]string, error)                          // every OCI region name
	Dial    func(ctx context.Context, network, address string) (net.Conn, error) // net.Dialer.DialContext in production
	Now     func() time.Time

	mu   sync.Mutex
	last map[string]time.Duration
	at   time.Time
}

// Run probes at start, then every RTTInterval, until ctx ends. A failed round is logged and the last one is kept.
func (p *Prober) Run(ctx context.Context) {
	ticker := time.NewTicker(RTTInterval)
	defer ticker.Stop()
	for {
		if err := p.Probe(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("round trip probe failed", observability.ComponentKey, sliceName, "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Probe measures one round and replaces the last one. A region that never connects is left out. A round that
// ends with ctx done keeps the last one, so shutdown does not empty the map.
func (p *Prober) Probe(ctx context.Context) error {
	regions, err := p.Regions(ctx)
	if err != nil {
		return fmt.Errorf("list OCI regions: %w", err)
	}
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		rtt = map[string]time.Duration{}
	)
	slots := make(chan struct{}, rttWorkers)
	for _, region := range regions {
		if !ociRegionName.MatchString(region) {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			if median, ok := p.median(ctx, region); ok {
				mu.Lock()
				rtt[region] = median
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	p.last, p.at = rtt, p.Now()
	p.mu.Unlock()
	return nil
}

// median connects RTTSamples times to region's endpoint and returns the median connect time of the connects that
// succeeded. Each connection is closed as soon as it is measured.
func (p *Prober) median(ctx context.Context, region string) (time.Duration, bool) {
	address := "objectstorage." + region + ".oraclecloud.com:443"
	var samples []time.Duration
	for range RTTSamples {
		attempt, cancel := context.WithTimeout(ctx, RTTTimeout)
		start := p.Now()
		conn, err := p.Dial(attempt, "tcp", address)
		cancel()
		if err != nil {
			continue
		}
		samples = append(samples, p.Now().Sub(start))
		_ = conn.Close()
	}
	if len(samples) == 0 {
		return 0, false
	}
	slices.Sort(samples)
	return samples[len(samples)/2], true
}

// Latest returns a copy of the last round's medians and when it finished. Both are empty before the first round.
func (p *Prober) Latest() (map[string]time.Duration, time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return maps.Clone(p.last), p.at
}
