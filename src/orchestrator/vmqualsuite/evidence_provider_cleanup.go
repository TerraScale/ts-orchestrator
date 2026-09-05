package vmqualsuite

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

// ProviderCleanupObservation contains one fresh post-cleanup observation for
// every exact local-provider path and listener. Success is represented by
// populated observations whose Present/Reachable values are false, not by an
// unexplained empty list.
type ProviderCleanupObservation struct {
	CapturedAt time.Time                            `json:"capturedAt"`
	Paths      []ProviderCleanupPathObservation     `json:"paths"`
	Listeners  []ProviderCleanupListenerObservation `json:"listeners"`
}

type ProviderCleanupPathObservation struct {
	Kind    string           `json:"kind"`
	Region  vmnet.RegionCode `json:"region,omitempty"`
	Path    string           `json:"path"`
	Present bool             `json:"present"`
}

type ProviderCleanupListenerObservation struct {
	Kind      string `json:"kind"`
	Address   string `json:"address"`
	Reachable bool   `json:"reachable"`
}

func (o ProviderCleanupObservation) Validate() error {
	if o.CapturedAt.IsZero() || len(o.Paths) < 4 || len(o.Listeners) < 6 {
		return errors.New("vmqual: provider cleanup observation is incomplete")
	}
	seenPaths := make(map[string]bool, len(o.Paths))
	for _, path := range o.Paths {
		if path.Kind == "" || !filepath.IsAbs(path.Path) || seenPaths[path.Path] || path.Present {
			return errors.New("vmqual: provider cleanup retained or duplicated an owned state path")
		}
		seenPaths[path.Path] = true
	}
	seenListeners := make(map[string]bool, len(o.Listeners))
	for _, listener := range o.Listeners {
		if listener.Kind == "" || listener.Address == "" || seenListeners[listener.Address] || listener.Reachable {
			return errors.New("vmqual: provider cleanup retained or duplicated an owned listener")
		}
		seenListeners[listener.Address] = true
	}
	return nil
}

type providerCleanupTarget struct {
	kind   string
	region vmnet.RegionCode
	path   string
}

// CleanupAndObserveProviderState closes every local provider endpoint,
// removes only its exact caller-owned persistent roots, and then re-observes
// every path and listener. Stack cleanup remains responsible for VM state.
func (d *LocalScenarioDriver) CleanupAndObserveProviderState(ctx context.Context) (ProviderCleanupObservation, error) {
	if d == nil || d.Endpoints == nil {
		return ProviderCleanupObservation{}, errors.New("vmqual: provider cleanup driver is not configured")
	}
	if ctx == nil {
		return ProviderCleanupObservation{}, errors.New("vmqual: provider cleanup context is nil")
	}
	if err := ctx.Err(); err != nil {
		return ProviderCleanupObservation{}, err
	}
	d.mu.Lock()
	stack, control := d.stack, d.control
	d.mu.Unlock()
	if stack == nil || control == nil || !filepath.IsAbs(stack.Config().StateRoot) {
		return ProviderCleanupObservation{}, errors.New("vmqual: provider cleanup ownership is incomplete")
	}
	stateRoot := filepath.Clean(stack.Config().StateRoot)
	resolvedStateRoot, err := filepath.EvalSymlinks(stateRoot)
	if err != nil || resolvedStateRoot != stateRoot {
		return ProviderCleanupObservation{}, errors.New("vmqual: provider cleanup state root is not a canonical non-symlink directory")
	}
	targets, err := d.providerCleanupTargets(stateRoot, control)
	if err != nil {
		return ProviderCleanupObservation{}, err
	}
	listeners, err := providerListenerTargets(d.Endpoints)
	if err != nil {
		return ProviderCleanupObservation{}, err
	}
	if err := d.Endpoints.Close(); err != nil {
		return ProviderCleanupObservation{}, err
	}
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return ProviderCleanupObservation{}, err
		}
		if err := vmqual.RemoveTreeAndSync(target.path); err != nil {
			return ProviderCleanupObservation{}, fmt.Errorf("vmqual: remove owned %s state: %w", target.kind, err)
		}
	}
	for _, parent := range []string{filepath.Join(stateRoot, "providers", "object"), filepath.Join(stateRoot, "providers")} {
		if err := os.Remove(parent); err != nil && !errors.Is(err, os.ErrNotExist) {
			return ProviderCleanupObservation{}, fmt.Errorf("vmqual: remove empty provider state parent: %w", err)
		}
	}
	if err := vmqual.SyncDirectory(stateRoot); err != nil {
		return ProviderCleanupObservation{}, fmt.Errorf("vmqual: sync provider cleanup state root: %w", err)
	}

	observation := ProviderCleanupObservation{CapturedAt: time.Now().UTC()}
	for _, target := range targets {
		present, observeErr := exactPathPresent(target.path)
		if observeErr != nil {
			return observation, observeErr
		}
		observation.Paths = append(observation.Paths, ProviderCleanupPathObservation{
			Kind: target.kind, Region: target.region, Path: target.path, Present: present,
		})
	}
	for _, listener := range listeners {
		reachable, observeErr := providerListenerReachable(ctx, listener.address)
		if observeErr != nil {
			return observation, observeErr
		}
		observation.Listeners = append(observation.Listeners, ProviderCleanupListenerObservation{
			Kind: listener.kind, Address: listener.address, Reachable: reachable,
		})
	}
	if err := observation.Validate(); err != nil {
		return observation, err
	}
	d.mu.Lock()
	stored := observation
	stored.Paths = append([]ProviderCleanupPathObservation(nil), observation.Paths...)
	stored.Listeners = append([]ProviderCleanupListenerObservation(nil), observation.Listeners...)
	d.cleanup = &stored
	d.mu.Unlock()
	return observation, nil
}

// ProviderCleanupEvidence returns a detached copy of the most recent fresh
// provider cleanup observation.
func (d *LocalScenarioDriver) ProviderCleanupEvidence() (ProviderCleanupObservation, bool) {
	if d == nil {
		return ProviderCleanupObservation{}, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cleanup == nil {
		return ProviderCleanupObservation{}, false
	}
	observation := *d.cleanup
	observation.Paths = append([]ProviderCleanupPathObservation(nil), d.cleanup.Paths...)
	observation.Listeners = append([]ProviderCleanupListenerObservation(nil), d.cleanup.Listeners...)
	return observation, true
}

func (d *LocalScenarioDriver) providerCleanupTargets(stateRoot string, control scenarioControlProof) ([]providerCleanupTarget, error) {
	controlRoot := control.JournalRoot()
	if controlRoot != filepath.Join(stateRoot, "control-contract") {
		return nil, errors.New("vmqual: control cleanup root differs from its owned state path")
	}
	targets := []providerCleanupTarget{{kind: "control-contract", path: controlRoot}}
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		store := d.Endpoints.Object[region]
		if store == nil {
			return nil, fmt.Errorf("vmqual: provider cleanup object store %s is missing", region)
		}
		root := filepath.Clean(store.Root())
		expected := filepath.Join(stateRoot, "providers", "object", strings.ToLower(string(region)))
		if root != expected || !vmqual.PathWithin(stateRoot, root) {
			return nil, fmt.Errorf("vmqual: provider cleanup object root %s is not owned", region)
		}
		targets = append(targets, providerCleanupTarget{kind: "object-store", region: region, path: root})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].path < targets[j].path })
	return targets, nil
}

type providerListenerTarget struct {
	kind    string
	address string
}

func providerListenerTargets(endpoints *LocalProviderEndpoints) ([]providerListenerTarget, error) {
	if endpoints == nil {
		return nil, errors.New("vmqual: provider endpoints are nil")
	}
	urls := []providerListenerTarget{
		{kind: "oci", address: endpoints.OCIURL},
		{kind: "cloudflare", address: endpoints.CloudflareURL},
		{kind: "edge", address: endpoints.EdgeURL},
	}
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		urls = append(urls, providerListenerTarget{kind: "object-" + strings.ToLower(string(region)), address: endpoints.ObjectURL[region]})
	}
	listeners := make([]providerListenerTarget, 0, len(urls))
	for _, target := range urls {
		parsed, err := url.Parse(target.address)
		if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.Path != "" {
			return nil, fmt.Errorf("vmqual: invalid owned %s listener URL", target.kind)
		}
		listeners = append(listeners, providerListenerTarget{kind: target.kind, address: parsed.Host})
	}
	sort.Slice(listeners, func(i, j int) bool { return listeners[i].kind < listeners[j].kind })
	return listeners, nil
}

func exactPathPresent(path string) (bool, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) == string(filepath.Separator) {
		return false, errors.New("vmqual: provider cleanup observation path is invalid")
	}
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func providerListenerReachable(ctx context.Context, address string) (bool, error) {
	if _, _, err := net.SplitHostPort(address); err != nil {
		return false, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", address)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	_ = connection.Close()
	return true, nil
}
