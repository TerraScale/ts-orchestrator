package pullrelease

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/nats-io/nats.go"
)

type found struct {
	release releaseattest.Release
	err     error
	checked time.Time
	seenTag string
	seenAt  time.Time
}

type finder struct {
	listed   time.Time
	failures int
	retry    time.Time
	seenTag  string
	seenAt   time.Time
}

func DiscoverSubject(region string) string { return protocol.MeshPullDiscoverPrefix + region }

func Ask(ctx context.Context, conn *nats.Conn, region string) (releasepush.Discovery, error) {
	message, err := conn.RequestWithContext(ctx, DiscoverSubject(region), nil)
	if errors.Is(err, nats.ErrNoResponders) {
		return releasepush.Discovery{Region: region}, nil
	}
	if err != nil {
		return releasepush.Discovery{}, err
	}
	var discovery releasepush.Discovery
	return discovery, json.Unmarshal(message.Data, &discovery)
}

func (u *Updater) watch(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		fresh := false
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-u.takeover:
			fresh = true
		}
		timer.Reset(u.poll(ctx, fresh))
	}
}

func (u *Updater) poll(ctx context.Context, fresh bool) time.Duration {
	if !u.leading.Load() {
		return u.Poll
	}
	result, due := u.find(ctx, fresh)
	var limited *releaseattest.RateLimitedError
	if result != nil && errors.As(result.err, &limited) {
		return max(due, time.Until(limited.Until))
	}
	return due
}

func (u *Updater) find(ctx context.Context, fresh bool) (*found, time.Duration) {
	u.finding.Lock()
	defer u.finding.Unlock()
	f := &u.finder
	if since := time.Since(f.listed); !fresh && since < u.Poll {
		return u.found.Load(), u.Poll - since
	}
	read, cancel := context.WithTimeout(ctx, discoverWait)
	release, err := u.newestRelease(read, fresh)
	cancel()
	f.listed = time.Now()
	now := f.listed.UTC()
	previous := u.found.Load()
	if release.SHA != "" && release.Tag() != f.seenTag {
		seen, err := u.store.Seen(ctx, release.Tag(), release.Seq, now)
		if err != nil {
			slog.WarnContext(ctx, "release discovery not recorded for the region; this process keeps its own time", "region", u.Region, "release", release.Tag(), "error", err)
		}
		f.seenTag, f.seenAt = release.Tag(), seen
		slog.InfoContext(ctx, "release discovered", "region", u.Region, "release", release.Tag(), "seq", release.Seq, "published", published(release), "discovered", seen)
	}
	result := &found{release: release, err: err, checked: now, seenTag: f.seenTag, seenAt: f.seenAt}
	u.found.Store(result)
	if result.differs(previous) {
		select {
		case u.wake <- struct{}{}:
		default:
		}
	}
	return result, u.Poll
}

func (f *found) differs(other *found) bool {
	return f != nil && (other == nil || other.release.Tag() != f.release.Tag() || other.release.Seq != f.release.Seq || errorText(other.err) != errorText(f.err))
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (u *Updater) newestRelease(ctx context.Context, fresh bool) (releaseattest.Release, error) {
	f := &u.finder
	if u.Channel != nil && (fresh || !time.Now().Before(f.retry)) {
		release, err := u.Channel.Newest(ctx)
		if err == nil || errors.Is(err, releaseattest.ErrRefused) {
			f.failures, f.retry = 0, time.Time{}
			return release, err
		}
		f.failures++
		backoff := u.Poll << min(f.failures-1, 3)
		f.retry = time.Now().Add(backoff + rand.N(backoff/2+1))
		slog.WarnContext(ctx, "release channel unreachable; using the GitHub release fallback", "region", u.Region, "error", err, "failures", f.failures, "channel_retry", f.retry)
	} else if u.Channel != nil {
		slog.WarnContext(ctx, "release channel backing off; using the GitHub release fallback", "region", u.Region, "channel_retry", f.retry)
	}
	return u.Source.Newest(ctx)
}

func (u *Updater) listen(ctx context.Context) {
	leading := u.leading.Load()
	switch {
	case leading && u.announced == nil:
		subscription, err := u.Conn.Subscribe(DiscoverSubject(u.Region), func(message *nats.Msg) { u.answer(ctx, message) })
		if err != nil {
			slog.WarnContext(ctx, "release announcements not received; the poll finds new releases", "region", u.Region, "error", err)
			return
		}
		u.announced = subscription
	case !leading && u.announced != nil:
		if err := u.announced.Unsubscribe(); err != nil {
			slog.WarnContext(ctx, "release announcement subscription not closed", "region", u.Region, "error", err)
		}
		u.announced = nil
	}
}

func (u *Updater) answer(ctx context.Context, message *nats.Msg) {
	discovery := releasepush.Discovery{Region: u.Region, Owner: u.Self}
	if u.leading.Load() {
		result, _ := u.find(ctx, true)
		discovery.Release, discovery.Seq, discovery.Discovered = result.release.Tag(), result.release.Seq, result.seenAt
		if result.release.SHA == "" {
			discovery.Release = ""
		}
		if result.err != nil {
			discovery.Error = result.err.Error()
		}
	} else {
		discovery.Owner = ""
	}
	data, err := json.Marshal(discovery)
	if err == nil {
		err = message.Respond(data)
	}
	if err != nil {
		slog.WarnContext(ctx, "release announcement not answered", "region", u.Region, "error", err)
	}
}
