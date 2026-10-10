package host

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
)

// Host load telemetry: the agent samples its own load every 15 seconds and
// sends it as the "load" host operation over its authenticated session; the
// authority leader hands accepted reports to the configured LoadSink. Load
// is telemetry only: it never changes a session, a desired state or any
// lifecycle decision on either side.

const (
	loadInterval = 15 * time.Second
	// minTerraBaseLoadTTL keeps recent member status through fast host polls.
	minTerraBaseLoadTTL = 5 * time.Second
	// maxLoadBackoff caps the retry spacing after failed publications, for
	// example while the controller has host telemetry disabled.
	maxLoadBackoff = 10 * time.Minute
	// terraBaseLoadTTL drops a TerraBase load block that no verified
	// member status refreshed recently.
	terraBaseLoadTTL = 2 * time.Minute
)

var (
	errLoadDisabled  = errors.New("host load telemetry is not enabled on this controller")
	errLoadThrottled = errors.New("host load report discarded inside the controller's minimum interval")
)

// LoadSink receives one authenticated host load report whose roles were
// restricted to current allocations, including roles with unknown usage.
// Origin comes from controller registration state, never from the report.
type LoadSink func(origin hostload.Origin, report hostload.Report) error

type loadAck struct {
	Accepted bool `json:"accepted"`
}

// SetLoadSink enables the "load" host operation; nil disables it again.
func (c *Controller) SetLoadSink(sink LoadSink) {
	if sink == nil {
		c.loadSink.Store(nil)
		return
	}
	c.loadSink.Store(&sink)
}

func (c *Controller) storeLoad(ctx context.Context, req request, r Registration) (any, error) {
	sink := c.loadSink.Load()
	if sink == nil {
		return nil, errLoadDisabled
	}
	var report hostload.Report
	if err := decodeStrict(req.Payload, &report); err != nil {
		return nil, err
	}
	if err := report.Validate(); err != nil {
		return nil, err
	}
	// Only roles registered for this host with a current, non-withdrawn
	// allocation count: a host cannot report load for a service it does
	// not run.
	roles := make([]hostload.RoleUsage, 0, len(r.Roles))
	for _, name := range r.Roles {
		desired, _, exists, err := c.readDesired(ctx, req.Node, name)
		if err != nil {
			return nil, err
		}
		if !exists || desired.Withdrawn {
			continue
		}
		if err := validateDesired(desired, c.cell, r); err != nil {
			continue
		}
		// Reservations survive missing cgroup measurements or a stopped process.
		role := hostload.RoleUsage{Role: name}
		for _, measured := range report.Roles {
			if measured.Role == name {
				role = measured
				break
			}
		}
		roles = append(roles, role)
	}
	report.Roles = roles
	err := (*sink)(hostload.Origin{Cell: c.cell, Environment: r.Environment, Node: req.Node}, report)
	if errors.Is(err, hostload.ErrTooFrequent) {
		return loadAck{Accepted: false}, nil
	}
	if err != nil {
		return nil, err
	}
	return loadAck{Accepted: true}, nil
}

// terraBaseLoad is the latest load block a verified member status carried.
type terraBaseLoad struct {
	load memberstatus.Load
	at   time.Time
}

// noteTerraBaseLoad remembers the load block of a member status that passed
// every identity, mount and serving check and was reported.
func (a *Agent) noteTerraBaseLoad(role string, load *memberstatus.Load) {
	a.loadMu.Lock()
	defer a.loadMu.Unlock()
	if load == nil {
		delete(a.terraBaseLoads, role)
		return
	}
	if a.terraBaseLoads == nil {
		a.terraBaseLoads = make(map[string]terraBaseLoad)
	}
	a.terraBaseLoads[role] = terraBaseLoad{load: *load, at: time.Now()}
}

func (a *Agent) currentTerraBaseLoads() map[string]memberstatus.Load {
	a.loadMu.Lock()
	defer a.loadMu.Unlock()
	// A running member's block is refreshed on every poll, so one that
	// missed a few polls (withdrawn, draining, or stuck) is dropped well
	// before the absolute cap.
	ttl := min(max(3*a.cfg.PollInterval, minTerraBaseLoadTTL), terraBaseLoadTTL)
	out := make(map[string]memberstatus.Load, len(a.terraBaseLoads))
	for role, entry := range a.terraBaseLoads {
		if time.Since(entry.at) > ttl {
			delete(a.terraBaseLoads, role)
			continue
		}
		out[role] = entry.load
	}
	return out
}

// cgroupRooted is implemented by runners that keep one cgroup v2 group per
// role under a common parent.
type cgroupRooted interface {
	CgroupRoot() string
}

// CgroupRoot is the role cgroup parent once Recover has run.
func (p *processRunner) CgroupRoot() string { return p.cgroups }

func (a *Agent) loadFilesystems() []observability.FilesystemRole {
	filesystems := []observability.FilesystemRole{{Role: "boot", Path: "/"}, {Role: "state", Path: a.cfg.StateRoot},
		{Role: "install", Path: a.cfg.InstallRoot}}
	if a.cfg.ManagedRuntimeRoot != "" {
		filesystems = append(filesystems, observability.FilesystemRole{Role: "managed_runtime", Path: a.cfg.ManagedRuntimeRoot})
	}
	if a.cfg.TerraBaseRoot != "" {
		filesystems = append(filesystems, observability.FilesystemRole{Role: "terrabase_data", Path: terrabase.Layout(a.cfg.TerraBaseRoot).Data()})
	}
	a.nativeRootMu.Lock()
	defer a.nativeRootMu.Unlock()
	// shortcut: generic S3 members have no tracked mount path; add runtime mount tracking when they need filesystem telemetry.
	for _, role := range a.cfg.Roles {
		root := a.nativeRoots[role]
		if root == nil {
			continue
		}
		select {
		case <-root.done:
			continue
		default:
		}
		member := filepath.Dir(root.path)
		filesystems = append(filesystems, observability.FilesystemRole{
			Role: "managed_volume_" + filepath.Base(member), Path: filepath.Join(member, "volume")})
	}
	return filesystems
}

// publishLoad samples and publishes host load until ctx ends. Failures back
// off exponentially up to maxLoadBackoff and are logged once per change of
// outcome, so a controller without telemetry costs one request per backoff.
func (a *Agent) publishLoad(ctx context.Context) {
	config := hostload.SamplerConfig{Roles: a.cfg.Roles,
		ReadSystem: func([]observability.FilesystemRole) (observability.SystemView, error) {
			return observability.ReadSystem(a.loadFilesystems())
		}}
	if rooted, ok := a.runner.(cgroupRooted); ok {
		config.CgroupRoot = rooted.CgroupRoot()
	}
	sampler := hostload.NewSampler(config)
	// The first sample only sets CPU baselines.
	sampler.Sample(nil)
	wait, failing := loadInterval, false
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if a.sessionLost.Load() {
			return
		}
		var ack loadAck
		err := a.request(ctx, "load", sampler.Sample(a.currentTerraBaseLoads()), &ack)
		if ctx.Err() != nil {
			return
		}
		if err := loadOutcome(err, ack); err != nil {
			if !failing {
				slog.Info("host load telemetry not accepted; backing off", "error_class", loadErrorClass(err))
			}
			failing = true
			wait = nextLoadWait(wait)
			continue
		}
		if failing {
			slog.Info("host load telemetry accepted")
		}
		failing, wait = false, loadInterval
	}
}

// nextLoadWait doubles the wait after a failed publication, capped at
// maxLoadBackoff, but never below the reporting interval.
func nextLoadWait(wait time.Duration) time.Duration {
	return max(min(wait*2, maxLoadBackoff), loadInterval)
}

// loadOutcome treats a reply whose sample the controller discarded (it
// arrived inside the controller's minimum interval) as a rejection that
// backs off, not as a success.
func loadOutcome(err error, ack loadAck) error {
	if err == nil && !ack.Accepted {
		return errLoadThrottled
	}
	return err
}

func loadErrorClass(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, errLoadThrottled):
		return "throttled"
	case strings.Contains(err.Error(), errLoadDisabled.Error()):
		return "disabled"
	default:
		return "other"
	}
}
