package pullrelease

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/ocirelease"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/nats-io/nats.go"
)

const (
	DefaultPoll       = 5 * time.Minute
	DefaultHealthyFor = 4 * time.Second
	DefaultDeadline   = 3 * time.Minute
	DefaultBakeFor    = 20 * time.Second

	checkEvery   = 2 * time.Second
	bakeFailures = 3
	askWait      = 8 * time.Second
	installWait  = 3*time.Minute + 30*time.Second
	discoverWait = time.Minute

	restartPending = "release restart pending"
)

type Host struct {
	ID   string
	Name string
}

type Updater struct {
	Region     string
	Self       string
	State      string
	Conn       *nats.Conn
	Fabric     *nats.Conn
	Hosts      func(context.Context) ([]Host, error)
	Services   func(context.Context) ([]Service, error)
	Source     *releaseattest.Source
	Channel    *ocirelease.Reader
	Attest     releaseattest.Verifier
	Client     *http.Client
	Poll       time.Duration
	HealthyFor time.Duration
	Deadline   time.Duration
	BakeFor    time.Duration
	StagingKey *ecdsa.PublicKey

	store      *Store
	status     Status
	revision   uint64
	leading    atomic.Bool
	sweepAfter time.Time
	wake       chan struct{}
	takeover   chan struct{}
	announced  *nats.Subscription
	found      atomic.Pointer[found]
	considered *found
	finding    sync.Mutex
	finder     finder
	watched    watch
	fetched    string
	checked    releaseattest.Release
	failed     string
}

func New(region, self, state string, conn, fabric *nats.Conn, handler *releasepush.Handler, hosts func(context.Context) ([]Host, error), services func(context.Context) ([]Service, error)) *Updater {
	signer, err := fleet.Embedded().Staging.Signer()
	if err != nil {
		panic(err)
	}
	return &Updater{Region: region, Self: self, State: state, Conn: conn, Fabric: fabric, Hosts: hosts, Services: services, StagingKey: signer,
		Source: handler.Source, Channel: &ocirelease.Reader{Registry: handler.Registry, Attest: handler.Attest}, Attest: handler.Attest, Client: handler.Client,
		Poll: DefaultPoll, HealthyFor: DefaultHealthyFor, Deadline: DefaultDeadline, BakeFor: DefaultBakeFor}
}

func (u *Updater) Run(ctx context.Context) error {
	u.wake, u.takeover = make(chan struct{}, 1), make(chan struct{}, 1)
	go u.lead(ctx)
	go u.watch(ctx)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		case <-u.wake:
		}
		next := u.turn(ctx)
		if u.found.Load().differs(u.considered) {
			next = min(next, checkEvery)
		}
		timer.Reset(next)
	}
}

func (u *Updater) lead(ctx context.Context) {
	tick := time.NewTicker(renewEvery)
	defer tick.Stop()
	for {
		if u.store == nil {
			store, err := Open(ctx, u.Fabric, u.Region, u.Region)
			if err != nil {
				slog.WarnContext(ctx, "pull rollout store unavailable", "error", err)
			}
			u.store = store
		}
		if u.store != nil {
			leading, err := u.store.Lead(ctx, u.Self)
			if err != nil {
				slog.WarnContext(ctx, "pull rollout lease not renewed", "error", err)
			}
			if u.leading.Swap(leading) != leading {
				slog.InfoContext(ctx, "pull rollout ownership changed", "region", u.Region, "owner", leading)
				if leading {
					select {
					case u.takeover <- struct{}{}:
					default:
					}
				}
			}
			u.listen(ctx)
			if !leading {
				stagingBlock.Store(nil)
			}
			if !leading {
				if status, _, err := u.store.Load(ctx); err == nil {
					u.mirror(ctx, status)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (u *Updater) turn(ctx context.Context) time.Duration {
	if !u.leading.Load() {
		return renewEvery
	}
	status, revision, err := u.store.Load(ctx)
	if err != nil {
		slog.WarnContext(ctx, "pull rollout record unreadable", "error", err)
		return renewEvery
	}
	u.status, u.revision = status, revision
	u.status.Region = u.Region
	if u.status.Owner != u.Self {
		slog.InfoContext(ctx, "taking over the region's pull rollout", "region", u.Region, "from", u.status.Owner, "phase", u.status.Phase)
		u.status.Owner = u.Self
		u.sweepAfter = time.Time{}
		if u.status.Phase == PhaseComplete && !u.status.settled() {
			u.status.Done = time.Now().UTC()
			u.status.Healthy, u.status.Failing, u.status.Failed, u.status.Failures = time.Time{}, time.Time{}, 0, 0
		}
		if !u.save(ctx) {
			return renewEvery
		}
	}
	return u.cycle(ctx)
}

func (u *Updater) cycle(ctx context.Context) time.Duration {
	u.settleRestart(ctx)
	if u.status.Phase == PhaseRollingBack && u.status.Target != nil {
		return u.restore(ctx)
	}
	if u.status.Phase == PhaseComplete && u.status.Target != nil && !u.status.settled() {
		return u.bake(ctx)
	}

	discovered := u.found.Load()
	if discovered == nil {
		return u.Poll
	}
	u.considered = discovered
	release, err := discovered.release, discovered.err
	u.status.Checked = discovered.checked
	if release.Seq != 0 {
		if release.Seq < u.status.Seq || release.Seq == u.status.Seq && (u.status.Target == nil || u.status.Target.Tag() != release.Tag()) {
			return u.ignore(ctx, fmt.Sprintf("channel seq %d (%s) is not newer than the region's seq %d; a replayed or rolled-back channel document is refused", release.Seq, release.Tag(), u.status.Seq))
		}
		u.status.Channel = release.Seq
	}
	var limited *releaseattest.RateLimitedError
	switch {
	case errors.Is(err, releaseattest.ErrRefused) && release.SHA == "":
		return u.ignore(ctx, err.Error())
	case errors.Is(err, releaseattest.ErrRefused):
		if !u.status.bad(release.Tag()) {
			u.refuse(ctx, release, err.Error())
		} else {
			u.save(ctx)
		}
		return u.Poll
	case errors.As(err, &limited):
		u.status.Reason = err.Error()
		u.save(ctx)
		return max(u.Poll, time.Until(limited.Until))
	case errors.Is(err, releaseattest.ErrNoRelease):
		u.status.Reason = err.Error()
		u.save(ctx)
		return u.Poll
	case err != nil:
		u.status.Reason = "release discovery: " + err.Error()
		u.save(ctx)
		return u.Poll
	}
	if u.status.bad(release.Tag()) {
		u.save(ctx)
		return u.Poll
	}
	if u.status.Target != nil && u.status.Target.Tag() == release.Tag() && release.Seq > u.status.Target.Seq {
		adopted := release
		u.status.Target, u.status.Seq = &adopted, max(u.status.Seq, release.Seq)
		slog.InfoContext(ctx, "the release channel names the current target; adopting its seq", "release", release.Tag(), "seq", release.Seq)
	}
	if u.status.Target == nil || u.status.Target.Tag() != release.Tag() {
		attested, err := u.verified(ctx, release)
		var missing *releaseattest.NotFoundError
		if errors.Is(err, releaseattest.ErrRefused) || errors.As(err, &missing) {
			u.refuse(ctx, release, err.Error())
			return u.Poll
		}
		if err != nil {
			u.status.Reason = "attestation check: " + err.Error()
			u.save(ctx)
			return u.Poll
		}
		if u.status.Target == nil {
			rows, refusal, waiting := u.formed(ctx, attested)
			if waiting != "" {
				u.status.Reason = "adoption of " + attested.Tag() + " waits: " + waiting
				u.save(ctx)
				return u.HealthyFor
			}
			if refusal != "" {
				u.status.Reason = "adoption of " + attested.Tag() + " refused: " + refusal
				u.save(ctx)
				return u.Poll
			}
			if rows != nil {
				now := time.Now().UTC()
				u.status = Status{Region: u.Region, Owner: u.Self, Phase: PhaseComplete, Target: &attested, Hosts: rows, Bad: u.status.Bad, Checked: u.status.Checked,
					Seq: max(u.status.Seq, attested.Seq), Channel: u.status.Channel, Published: published(attested), Discovered: now, Adopted: now}
				slog.InfoContext(ctx, "the region formed on the attested release: every host booted it and none holds an install receipt; adopted without a rollout or a gate", "release", attested.Tag())
				if !u.save(ctx) {
					return renewEvery
				}
				return u.Poll
			}
		}
		u.prefetch(ctx, attested)
		reason := u.admission(ctx, attested.Tag())
		if reason == "" && u.Region == catalog.RolloutOrder()[0] {
			if reason := u.staged(ctx, attested); reason != "" {
				u.status.Reason = reason
				u.save(ctx)
				return checkEvery
			}
		}
		if reason == "" {
			decided, err := u.store.admit(ctx, attested.Tag(), u.Region)
			if err != nil {
				decided = "rollout decision of " + attested.Tag() + " unreadable: " + err.Error()
			}
			reason = decided
		}
		if reason != "" {
			u.status.Reason = reason
			u.save(ctx)
			return checkEvery
		}
		slog.InfoContext(ctx, "attested release found; rolling it out", "release", attested.Tag())
		seen := time.Now().UTC()
		if discovered.seenTag == attested.Tag() {
			seen = discovered.seenAt
		}
		u.status = Status{Region: u.Region, Owner: u.Self, Phase: PhaseRolling, Target: &attested, Bad: u.status.Bad, Checked: u.status.Checked,
			Seq: max(u.status.Seq, attested.Seq), Channel: u.status.Channel, Published: published(attested), Discovered: seen}
		if !u.save(ctx) {
			return renewEvery
		}
	}
	if !u.status.Adopted.IsZero() {
		return u.adoptedSweep(ctx)
	}
	if u.status.Phase == PhaseComplete && u.status.settled() && time.Now().Before(u.sweepAfter) {
		return time.Until(u.sweepAfter)
	}
	return u.roll(ctx)
}

func (u *Updater) formed(ctx context.Context, release releaseattest.Release) ([]HostProgress, string, string) {
	hosts, err := u.Hosts(ctx)
	if err != nil || len(hosts) == 0 {
		return nil, "", fmt.Sprintf("host inventory unavailable: %v", err)
	}
	rows := make([]HostProgress, 0, len(hosts))
	var unknown, silent []string
	for _, host := range hosts {
		reply, err := u.ask(ctx, host.ID, releasepush.PullRequest{Op: releasepush.PullStatus}, askWait)
		if err != nil {
			silent = append(silent, host.Name+" does not answer: "+err.Error())
			continue
		}
		want, built := release.Binaries[reply.Arch]
		if !built || reply.Version != release.SHA || reply.SHA256 != want.SHA256 || reply.Provenance == releasepush.ProvenanceInstalled {
			return nil, "", ""
		}
		switch {
		case reply.State != "":
			unknown = append(unknown, host.Name+" is in release "+reply.State)
		case reply.Provenance != releasepush.ProvenanceBooted:
			unknown = append(unknown, host.Name+" install history unknown: "+cmp.Or(reply.Provenance, "not reported"))
		}
		rows = append(rows, HostProgress{ID: host.ID, Host: host.Name, State: HostDone, Version: release.SHA, SHA256: want.SHA256})
	}
	if len(unknown) != 0 {
		return nil, strings.Join(unknown, "; "), ""
	}
	if len(silent) != 0 {
		return nil, "", strings.Join(silent, "; ")
	}
	for _, row := range rows {
		reply, err := u.ask(ctx, row.ID, releasepush.PullRequest{Op: releasepush.PullAdopt, Release: release}, installWait)
		if err != nil || reply.State != releasepush.StateAdopted {
			return nil, fmt.Sprintf("%s did not record the release it booted: %v %s", row.Host, err, reply.Error), ""
		}
	}
	return rows, "", ""
}

func (u *Updater) adoptedSweep(ctx context.Context) time.Duration {
	target := *u.status.Target
	hosts, err := u.Hosts(ctx)
	if err != nil {
		u.status.Reason = "host inventory unavailable: " + err.Error()
		u.save(ctx)
		return u.Poll
	}
	var reasons []string
	for _, host := range hosts {
		if u.status.host(host.ID) == nil {
			u.status.Hosts = append(u.status.Hosts, HostProgress{ID: host.ID, Host: host.Name, State: HostPending})
		}
		row := u.status.host(host.ID)
		reply, err := u.ask(ctx, host.ID, releasepush.PullRequest{Op: releasepush.PullStatus}, askWait)
		if err != nil {
			reasons = append(reasons, host.Name+" does not answer: "+err.Error())
			continue
		}
		row.Version, row.SHA256 = reply.Version, reply.SHA256
		want, built := target.Binaries[reply.Arch]
		if !built || reply.Version != target.SHA || reply.SHA256 != want.SHA256 {
			row.State = HostPending
			reasons = append(reasons, host.Name+" runs "+reply.Version+", not the adopted "+target.Tag()+"; it takes the next release")
			continue
		}
		if target.Seq != 0 && reply.Seq != target.Seq {
			recorded, err := u.ask(ctx, host.ID, releasepush.PullRequest{Op: releasepush.PullAdopt, Release: target}, installWait)
			if err != nil || recorded.State != releasepush.StateAdopted {
				reasons = append(reasons, fmt.Sprintf("%s did not record seq %d of %s: %v %s", host.Name, target.Seq, target.Tag(), err, recorded.Error))
				continue
			}
		}
		row.State, row.Error = HostDone, ""
	}
	u.status.Reason = strings.Join(reasons, "; ")
	u.save(ctx)
	return u.Poll
}

func published(release releaseattest.Release) time.Time {
	if release.Channel == nil {
		return time.Time{}
	}
	channel, err := releaseattest.ParseChannel(release.Channel.Document)
	if err != nil {
		return time.Time{}
	}
	return channel.PublishedAt
}

func (u *Updater) attested(ctx context.Context, release releaseattest.Release) (releaseattest.Release, error) {
	if release.Channel != nil {
		return release, nil
	}
	verify, cancel := context.WithTimeout(ctx, discoverWait)
	defer cancel()
	return u.Attest.Attested(verify, u.Client, release)
}

func (u *Updater) verified(ctx context.Context, release releaseattest.Release) (releaseattest.Release, error) {
	if u.checked.SHA == release.SHA && u.checked.Tag() == release.Tag() && u.checked.Seq == release.Seq {
		return u.checked, nil
	}
	attested, err := u.attested(ctx, release)
	if err == nil {
		u.checked = attested
	}
	return attested, err
}

func (u *Updater) roll(ctx context.Context) time.Duration {
	target := *u.status.Target
	if reason := u.recordBaseline(ctx); reason != "" {
		return u.wait(ctx, reason)
	}
	hosts, err := u.Hosts(ctx)
	if err != nil || len(hosts) == 0 {
		return u.wait(ctx, fmt.Sprintf("host inventory unavailable: %v", err))
	}
	slices.SortFunc(hosts, func(a, b Host) int {
		return cmp.Or(cmp.Compare(boolRank(!u.inFlight(a.ID)), boolRank(!u.inFlight(b.ID))),
			cmp.Compare(boolRank(a.ID == u.Self), boolRank(b.ID == u.Self)), cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID))
	})
	progress := make([]HostProgress, 0, len(hosts))
	for _, host := range hosts {
		row := HostProgress{ID: host.ID, Host: host.Name, State: HostPending}
		if known := u.status.host(host.ID); known != nil {
			row = *known
		}
		progress = append(progress, row)
	}
	u.status.Hosts = progress
	if u.status.Phase != PhaseRolledBack && u.status.Phase != PhaseRefused {
		u.status.Phase = PhaseRolling
	}
	for _, host := range hosts {
		if !u.leading.Load() {
			return renewEvery
		}
		row := u.status.host(host.ID)
		reply, err := u.ask(ctx, host.ID, releasepush.PullRequest{Op: releasepush.PullStatus}, askWait)
		if err != nil {
			return u.wait(ctx, host.Name+" does not answer: "+err.Error())
		}
		if row.State == HostNewer && row.Version == reply.Version {
			continue
		}
		row.Version, row.SHA256 = reply.Version, reply.SHA256
		want, ok := target.Binaries[reply.Arch]
		if !ok {
			return u.wait(ctx, fmt.Sprintf("%s runs %q, which the release does not build", host.Name, reply.Arch))
		}
		onTarget := reply.Version == target.SHA && reply.SHA256 == want.SHA256
		unrecorded := target.Seq != 0 && reply.Seq != target.Seq
		if onTarget && row.State == HostDone && !unrecorded {
			continue
		}
		if onTarget && reply.State == "" && reply.Health != restartPending && !u.inFlight(host.ID) {
			if unrecorded {
				recorded, err := u.ask(ctx, host.ID, releasepush.PullRequest{Op: releasepush.PullAdopt, Release: target}, installWait)
				if err != nil || recorded.State != releasepush.StateAdopted {
					return u.wait(ctx, fmt.Sprintf("%s already runs %s but did not record its seq: %v %s", host.Name, target.Tag(), err, cmp.Or(refusalReason(recorded), recorded.Error, recorded.State)))
				}
			}
			row.State, row.Error = HostDone, ""
			u.save(ctx)
			continue
		}
		if !onTarget && reply.Health != restartPending && row.State == HostGating {
			return u.rolledBack(ctx, row, "rolled back by its own probation: "+reply.Error)
		}
		if (!onTarget || unrecorded) && reply.Health != restartPending {
			if reason := u.regionReady(ctx, host.ID); reason != "" {
				return u.wait(ctx, reason)
			}
			if reason := u.claimRestart(ctx, host.ID, reply); reason != "" {
				return u.wait(ctx, reason)
			}
			row.State, row.Error = HostInstalling, ""
			if !u.save(ctx) {
				return renewEvery
			}
			reply, err = u.ask(ctx, host.ID, releasepush.PullRequest{Op: releasepush.PullInstall, Release: target}, installWait)
			if err != nil {
				return u.wait(ctx, host.Name+" install has no answer: "+err.Error())
			}
			switch {
			case reply.State == "installed" || reply.State == "current":
				row.Installed = time.Now().UTC()
			case reply.State == releasepush.StateNewer:
				row.State = HostNewer
				continue
			case reply.State == "rolled_back":
				return u.rolledBack(ctx, row, "this release was already rolled back: "+reply.Error)
			case reply.Refusal != nil && reply.Refusal.Kind == releasepush.RefusalIntegrity:
				row.Error = reply.Refusal.Reason
				u.refuse(ctx, target, host.Name+" refused the release: "+reply.Refusal.Reason)
				return u.Poll
			default:
				row.State = HostPending
				return u.wait(ctx, host.Name+" did not install: "+cmp.Or(refusalReason(reply), reply.Error, reply.State))
			}
		}
		if row.Installed.IsZero() {
			row.Installed = cmp.Or(reply.Started, time.Now()).UTC()
		}
		row.State = HostGating
		u.save(ctx)
		if host.ID == u.Self && !onTarget {
			slog.InfoContext(ctx, "installed the release on this host; its new process finishes the rollout", "release", target.Tag())
			return u.Poll
		}
		if err := u.gate(ctx, host, target, want); err != nil {
			if errors.Is(err, errChanged) {
				return renewEvery
			}
			return u.rolledBack(ctx, row, err.Error())
		}
		row.State, row.Error, row.Version, row.SHA256, row.Ready = HostDone, "", target.SHA, want.SHA256, time.Now().UTC()
		u.save(ctx)
		u.settleRestart(ctx)
	}
	u.status.Phase, u.status.Reason = PhaseComplete, ""
	if u.status.Done.IsZero() {
		u.status.Done = time.Now().UTC()
	}
	if !slices.ContainsFunc(u.status.Hosts, func(row HostProgress) bool { return row.State != HostNewer }) {
		u.status.Phase, u.status.Reason = PhaseNewer, "every host already runs a release that descends from "+target.Tag()
	}
	if !u.save(ctx) {
		return renewEvery
	}
	switch {
	case u.status.Phase == PhaseComplete && !u.status.settled():
		return u.bake(ctx)
	case u.status.Phase == PhaseComplete:
		return u.complete(ctx)
	}
	return u.Poll
}

func (u *Updater) inFlight(id string) bool {
	row := u.status.host(id)
	return row != nil && (row.State == HostInstalling || row.State == HostGating)
}

func boolRank(last bool) int {
	if last {
		return 1
	}
	return 0
}

func refusalReason(reply releasepush.Reply) string {
	if reply.Refusal == nil {
		return ""
	}
	return reply.Refusal.Reason
}

func (u *Updater) regionReady(ctx context.Context, except string) string {
	hosts, err := u.Hosts(ctx)
	if err != nil {
		return "host inventory unavailable: " + err.Error()
	}
	for _, host := range hosts {
		if host.ID == except {
			continue
		}
		reply, err := u.ask(ctx, host.ID, releasepush.PullRequest{Op: releasepush.PullStatus}, askWait)
		switch {
		case err != nil:
			return host.Name + " does not answer: " + err.Error()
		case reply.State != "":
			return host.Name + " is in release " + reply.State
		}
		if worse := u.status.Baseline.worseHost(host.ID, reply.Health); worse != "" {
			return host.Name + " is worse than before the release: " + worse
		}
	}
	if _, found := u.judgeServices(ctx); found.worse != "" {
		return "region worse than before the release: " + found.worse
	}
	return ""
}

func (u *Updater) gate(ctx context.Context, host Host, target releaseattest.Release, want releaseattest.Artifact) error {
	deadline := time.Now().Add(u.Deadline)
	var healthySince time.Time
	last := "no answer"
	tick := time.NewTicker(checkEvery)
	defer tick.Stop()
	for {
		reply, err := u.ask(ctx, host.ID, releasepush.PullRequest{Op: releasepush.PullStatus}, askWait)
		healthy := false
		switch {
		case err != nil:
			last = "no answer: " + err.Error()
		case reply.Health == restartPending:
			last = restartPending
		case reply.Version != target.SHA || reply.SHA256 != want.SHA256:
			return fmt.Errorf("%s left the release; it runs %s %s: %s", host.Name, reply.Version, reply.SHA256, reply.Error)
		case reply.State != "":
			last = "release " + reply.State
		default:
			if worse := u.status.Baseline.worseHost(host.ID, reply.Health); worse != "" {
				last = worse
			} else if _, found := u.judgeServices(ctx); found.worse != "" {
				last = "region: " + found.worse
			} else {
				healthy = true
			}
		}
		if !u.leading.Load() {
			return errChanged
		}
		u.settleRestart(ctx)
		now := time.Now()
		if !healthy {
			healthySince = time.Time{}
		} else if healthySince.IsZero() {
			healthySince = now
		}
		if healthy && now.Sub(healthySince) >= u.HealthyFor {
			return nil
		}
		if now.After(deadline) {
			return fmt.Errorf("%s not healthy for %s within %s: %s", host.Name, u.HealthyFor, u.Deadline, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func (u *Updater) rolledBack(ctx context.Context, row *HostProgress, reason string) time.Duration {
	row.State, row.Error = HostRestoring, reason
	u.status.Phase, u.status.Reason, u.status.Since = PhaseRollingBack, row.Host+": "+reason, time.Now().UTC()
	u.save(ctx)
	u.recordFailure(ctx)
	slog.WarnContext(ctx, "release failed on a host; restoring its previous binary", "release", u.status.Target.Tag(), "host", row.Host, "reason", reason)
	return checkEvery
}

func (u *Updater) restore(ctx context.Context) time.Duration {
	target := *u.status.Target
	u.recordFailure(ctx)
	var row *HostProgress
	for i := range u.status.Hosts {
		if u.status.Hosts[i].State == HostRestoring {
			row = &u.status.Hosts[i]
			break
		}
	}
	if row == nil {
		u.status.Phase = PhaseRolledBack
		u.status.markBad(target.Tag())
		u.save(ctx)
		return u.Poll
	}
	if limit := 2 * u.Deadline; time.Since(u.status.Since) > limit {
		u.status.Phase = PhaseStalled
		u.status.Reason = fmt.Sprintf("critical: %s still runs %s; its previous binary was not confirmed within %s: %s", row.Host, target.Tag(), limit, u.status.Reason)
		u.status.markBad(target.Tag())
		u.save(ctx)
		slog.ErrorContext(ctx, "release rollback stalled; the pull rollout stops holding the region", "release", target.Tag(), "host", row.Host, "reason", u.status.Reason)
		return u.Poll
	}
	running, err := releasepush.AskVersion(ctx, u.Conn, u.Region, row.ID)
	if err != nil {
		return u.restoring(ctx, row, "does not answer: "+err.Error())
	}
	row.Version, row.SHA256 = running.Version, running.SHA256
	if running.Version == target.SHA && builds(target, running.SHA256) {
		reply, err := u.ask(ctx, row.ID, releasepush.PullRequest{Op: releasepush.PullStatus}, askWait)
		switch {
		case err != nil:
			return u.restoring(ctx, row, "does not answer: "+err.Error())
		case reply.Health == restartPending:
			return u.restoring(ctx, row, "restoring the previous binary")
		}
		if reason := u.claimRestart(ctx, row.ID, reply); reason != "" {
			return u.restoring(ctx, row, reason)
		}
		if !u.save(ctx) {
			return renewEvery
		}
		restored, err := u.ask(ctx, row.ID, releasepush.PullRequest{Op: releasepush.PullRollback, Release: target, Reason: row.Error}, askWait)
		if err != nil || restored.State != "restoring" {
			return u.restoring(ctx, row, fmt.Sprintf("restoring the previous binary failed: %v %s", err, restored.Error))
		}
		return u.restoring(ctx, row, "restoring the previous binary")
	}
	if running.State != "" {
		return u.restoring(ctx, row, "previous binary not confirmed yet: "+running.State+" "+running.Error)
	}
	row.State = HostRolledBack
	u.status.Phase, u.status.Reason = PhaseRolledBack, row.Host+": "+row.Error
	u.status.markBad(target.Tag())
	u.save(ctx)
	slog.WarnContext(ctx, "release rolled back; the host runs its previous binary", "release", target.Tag(), "host", row.Host, "version", running.Version)
	return u.Poll
}

func (u *Updater) restoring(ctx context.Context, row *HostProgress, reason string) time.Duration {
	u.status.Reason = row.Host + ": " + reason
	u.save(ctx)
	return checkEvery
}

func builds(release releaseattest.Release, digest string) bool {
	for _, artifact := range release.Binaries {
		if artifact.SHA256 == digest {
			return true
		}
	}
	return false
}

func (u *Updater) refuse(ctx context.Context, release releaseattest.Release, reason string) {
	slog.WarnContext(ctx, "release refused", "release", release.Tag(), "reason", reason)
	u.status.Phase, u.status.Reason = PhaseRefused, release.Tag()+": "+reason
	u.status.Target = &release
	for i := range u.status.Hosts {
		if u.status.Hosts[i].State != HostDone {
			u.status.Hosts[i].State = HostPending
		}
	}
	u.status.markBad(release.Tag())
	u.save(ctx)
}

func (u *Updater) ignore(ctx context.Context, reason string) time.Duration {
	if u.status.Reason != reason {
		slog.WarnContext(ctx, "release channel refused; the rollout record keeps its target", "reason", reason)
	}
	u.status.Reason = reason
	u.save(ctx)
	return u.Poll
}

func (u *Updater) wait(ctx context.Context, reason string) time.Duration {
	if u.status.Phase != PhaseRolledBack && u.status.Phase != PhaseRefused {
		u.status.Phase = PhaseWaiting
	}
	u.status.Reason = reason
	u.save(ctx)
	return u.HealthyFor
}

func (u *Updater) ask(ctx context.Context, host string, request releasepush.PullRequest, wait time.Duration) (releasepush.Reply, error) {
	data, err := json.Marshal(request)
	if err != nil {
		return releasepush.Reply{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	message, err := u.Conn.RequestWithContext(ctx, releasepush.PullSubject(u.Region, host), data)
	if err != nil {
		return releasepush.Reply{}, err
	}
	var reply releasepush.Reply
	if err := protocol.DecodeTolerant(message.Data, &reply, 64<<10); err != nil {
		return releasepush.Reply{}, err
	}
	return reply, nil
}

func (u *Updater) save(ctx context.Context) bool {
	u.status.Updated = time.Now().UTC()
	revision, err := u.store.Save(ctx, u.status, u.revision)
	if err != nil {
		slog.WarnContext(ctx, "pull rollout record not saved; this manager stops until it reads it again", "error", err)
		return false
	}
	u.revision = revision
	u.mirror(ctx, u.status)
	data, err := json.Marshal(u.status)
	if err == nil {
		err = u.Conn.Publish(protocol.MeshPullProgressPrefix+u.Region, data)
	}
	if err != nil {
		slog.WarnContext(ctx, "pull rollout progress not published", "error", err)
	}
	return true
}

func (u *Updater) mirror(ctx context.Context, status Status) {
	if err := write(u.State, status); err != nil {
		slog.WarnContext(ctx, "pull rollout record not mirrored for the host's health report", "error", err)
	}
	if err := releasepush.RecordChannelSeq(u.State, status.Channel); err != nil {
		slog.WarnContext(ctx, "release channel seq not recorded for the host's metrics", "error", err)
	}
}

func (u *Updater) admission(ctx context.Context, tag string) string {
	if u.Region == fleet.Embedded().Staging.Label {
		return ""
	}
	order := catalog.RolloutOrder()
	if !slices.Contains(order, u.Region) {
		return "region has no reviewed binary rollout position"
	}
	if reason, err := u.store.failed(ctx, tag); err != nil || reason != "" {
		return cmp.Or(reason, "rollout decision of "+tag+" unreadable: "+fmt.Sprint(err))
	}
	canary := order[0]
	if u.Region == canary {
		return ""
	}
	status, err := u.store.loadFromLeader(ctx, canary)
	switch {
	case err != nil:
		return canary + ": rollout record unreadable: " + err.Error()
	case status.Target == nil || status.Target.Tag() != tag || status.Phase != PhaseComplete || status.Done.IsZero() || !status.passed():
		return canary + ": waiting for the canary region to pass the regional gate of the same release"
	}
	return ""
}

func (u *Updater) prefetch(ctx context.Context, release releaseattest.Release) {
	if u.fetched == release.Tag() {
		return
	}
	hosts, err := u.Hosts(ctx)
	if err != nil {
		slog.WarnContext(ctx, "release not fetched in advance; each host downloads it at its install", "release", release.Tag(), "error", err)
		return
	}
	u.fetched = release.Tag()
	for _, host := range hosts {
		go func() {
			reply, err := u.ask(ctx, host.ID, releasepush.PullRequest{Op: releasepush.PullFetch, Release: release}, installWait)
			if err != nil || reply.Error != "" {
				slog.WarnContext(ctx, "release not fetched in advance; the host downloads it at its install", "release", release.Tag(), "host", host.Name, "error", err, "reply", reply.Error)
			}
		}()
	}
}

func (u *Updater) bake(ctx context.Context) time.Duration {
	if !slices.ContainsFunc(u.status.Hosts, installedHere) {
		u.status.Adopted = time.Now().UTC()
		u.status.Reason = "no host installed " + u.status.Target.Tag() + " in this rollout; nothing to gate or roll back"
		u.save(ctx)
		return u.Poll
	}
	if reason := u.recordBaseline(ctx); reason != "" {
		u.status.Reason = reason
		u.save(ctx)
		return checkEvery
	}
	now := time.Now().UTC()
	failed, check, failure, found, restarted := u.bakeSample(ctx)
	if found.excluded != "" {
		u.status.Excluded = found.excluded
	}
	if restarted {
		return u.rolledBack(ctx, u.rollbackTarget(failed), "regional gate: "+failure)
	}
	if failure != "" && found.excluded != "" {
		failure += "; " + found.excluded
	}
	if failure != "" {
		slog.WarnContext(ctx, "regional gate sample failed", "release", u.status.Target.Tag(), "check", check, "failure", failure)
		if u.status.Failed == 0 {
			u.status.Failing = now
		}
		u.status.Failed++
		u.status.Failures++
		u.status.Healthy = time.Time{}
		if u.status.Failed >= bakeFailures && now.Sub(u.status.Failing) >= rollout.BakeFailureDuration {
			return u.rolledBack(ctx, u.rollbackTarget(failed), fmt.Sprintf("regional bake failed in %d samples over %s: %s", u.status.Failed, now.Sub(u.status.Failing).Round(time.Second), failure))
		}
		if bound := u.bakeBound(); now.Sub(u.status.Done) >= bound {
			return u.rolledBack(ctx, u.rollbackTarget(failed), fmt.Sprintf("regional bake found no healthy %s window within %s: %d failed samples, the last: %s", u.BakeFor, bound, u.status.Failures, failure))
		}
		u.status.Reason = "regional bake sample failed: " + failure
		u.save(ctx)
		return checkEvery
	}
	if found.excluded != "" {
		u.status.Failing, u.status.Failed, u.status.Healthy = time.Time{}, 0, time.Time{}
		if bound := u.bakeBound(); len(found.unsettled) != 0 && now.Sub(u.status.Done) >= bound {
			u.status.Withheld = "app " + strings.Join(found.unsettled, ", ") + " unsettled"
			u.status.Reason = fmt.Sprintf("withheld: %s within %s of the gate start (%s); later regions hold %s and this region takes the next release", u.status.Withheld, bound, found.excluded, u.status.Target.Tag())
			slog.WarnContext(ctx, "regional gate withheld: an app's own release did not settle within the bound", "release", u.status.Target.Tag(), "excluded", found.excluded)
			u.save(ctx)
			u.sweepAfter = time.Now().Add(u.Poll)
			return u.Poll
		}
		u.status.Reason = "regional bake waits for services in their own release to settle: " + found.excluded
		u.save(ctx)
		return checkEvery
	}
	if u.status.Failed != 0 || u.status.Healthy.IsZero() || u.status.Reason != "" {
		u.status.Failing, u.status.Failed, u.status.Reason = time.Time{}, 0, ""
		if u.status.Healthy.IsZero() {
			u.status.Healthy = now
		}
		u.save(ctx)
	}
	if now.Sub(u.status.Healthy) < u.BakeFor || now.Sub(u.status.Done) < u.BakeFor {
		return checkEvery
	}
	u.status.Passed = now
	if !u.save(ctx) {
		return renewEvery
	}
	return u.complete(ctx)
}

func (u *Updater) complete(ctx context.Context) time.Duration {
	if u.Region == fleet.Embedded().Staging.Label && u.status.passed() {
		if err := u.publishStaging(ctx); err != nil {
			slog.WarnContext(ctx, "staging completion not published; production stays on its release", "release", u.status.Target.Tag(), "error", err)
			u.status.Reason = "staging completion not published: " + err.Error()
			u.save(ctx)
		}
	}
	u.sweepAfter = time.Now().Add(u.Poll)
	return u.Poll
}

func installedHere(row HostProgress) bool {
	return !row.Installed.IsZero()
}

func (u *Updater) rollbackTarget(failed *HostProgress) *HostProgress {
	if failed != nil && installedHere(*failed) {
		return failed
	}
	var target *HostProgress
	for i := range u.status.Hosts {
		row := &u.status.Hosts[i]
		if installedHere(*row) && (target == nil || row.Installed.After(target.Installed)) {
			target = row
		}
	}
	return target
}

func (u *Updater) bakeBound() time.Duration {
	return 2*u.BakeFor + rollout.BakeFailureDuration
}

func (u *Updater) bakeSample(ctx context.Context) (*HostProgress, string, string, judgement, bool) {
	if !u.watched.done.Equal(u.status.Done) {
		u.watched = watch{done: u.status.Done, tasks: map[string][]string{}, versions: map[string][2]int64{}}
	}
	var failed *HostProgress
	check, failure := "", ""
	for i := range u.status.Hosts {
		host := &u.status.Hosts[i]
		if host.State == HostNewer {
			continue
		}
		reply, err := u.ask(ctx, host.ID, releasepush.PullRequest{Op: releasepush.PullStatus}, askWait)
		if err == nil && reply.Started.After(u.status.Done) {
			return host, "restart", fmt.Sprintf("%s orchestrator restarted at %s, after the gate began", host.Host, reply.Started.UTC().Format(time.RFC3339)), judgement{}, true
		}
		if failure != "" {
			continue
		}
		if err != nil || reply.State != "" || reply.Version != host.Version || reply.SHA256 != host.SHA256 {
			failed, check, failure = host, "host status", fmt.Sprintf("%s: %v %s %s %s", host.Host, err, reply.State, reply.Health, reply.Error)
		} else if worse := u.status.Baseline.worseHost(host.ID, reply.Health); worse != "" {
			failed, check, failure = host, "host health", host.Host+": "+worse
		}
	}
	services, found := u.judgeServices(ctx)
	if restart := u.watched.restarted(u.status.Baseline, services, found.released); restart != "" {
		return nil, "restart", restart, found, true
	}
	if failure == "" && found.worse != "" {
		check, failure = "region services", found.worse
	}
	return failed, check, failure, found, false
}
