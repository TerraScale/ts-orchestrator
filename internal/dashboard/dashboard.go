package dashboard

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

const (
	// DefaultInterval is how often a page stream re-renders its section.
	// Snapshot sections are cached for three seconds underneath, so a tick
	// never walks JetStream or /proc more often than a scrape does.
	DefaultInterval = 2 * time.Second
	// DefaultMaxStreams caps concurrent live page streams on one listener.
	DefaultMaxStreams = 16
	// clusterCacheTTL shares one cell-wide scatter-gather between every open
	// page stream instead of issuing one NATS request per browser tick.
	clusterCacheTTL = 2 * time.Second
	recentEvents    = 200
)

// Options wires the read-only providers the dashboard renders. Snapshots and
// Cluster may be attached later with SetSnapshots and SetCluster, because a
// controller only builds them once its broker and authority are open; until
// then the pages say the member is still starting.
type Options struct {
	Health    observability.ReadinessSource
	Events    observability.EventSource
	Snapshots observability.SnapshotSource
	Cluster   observability.ClusterSource
	// Interval and MaxStreams default to DefaultInterval and
	// DefaultMaxStreams.
	Interval   time.Duration
	MaxStreams int
	// SignOut shows the sign-out control; set it when the listener issues
	// browser sessions.
	SignOut bool
	// RequireLiteralHost refuses requests whose Host header is a DNS name
	// other than localhost. A tokenless loopback listener sets it so a page
	// on another site cannot read the dashboard through DNS rebinding.
	RequireLiteralHost bool
	// Now replaces time.Now in tests.
	Now func() time.Time
}

// Dashboard is the operator dashboard of one member. It only reads provider
// views and never mutates control-plane state.
type Dashboard struct {
	options   Options
	snapshots atomic.Pointer[snapshotHolder]
	cluster   atomic.Pointer[clusterHolder]
	streams   chan struct{}
	clusters  observability.Cache[observability.ClusterSnapshot]
}

type snapshotHolder struct{ source observability.SnapshotSource }
type clusterHolder struct{ source observability.ClusterSource }

// Mounter is the private listener the dashboard mounts on. Handle must
// authenticate; HandleStatic serves the public embedded assets only.
// *observability.Server implements it.
type Mounter interface {
	Handle(pattern string, handler http.Handler)
	HandleStatic(pattern string, handler http.Handler)
	HandleLogin(page http.Handler)
}

// New builds a dashboard over the given providers.
func New(options Options) *Dashboard {
	if options.Interval <= 0 {
		options.Interval = DefaultInterval
	}
	if options.MaxStreams <= 0 {
		options.MaxStreams = DefaultMaxStreams
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	dashboard := &Dashboard{options: options, streams: make(chan struct{}, options.MaxStreams)}
	dashboard.clusters.TTL = clusterCacheTTL
	dashboard.SetSnapshots(options.Snapshots)
	dashboard.SetCluster(options.Cluster)
	return dashboard
}

// SetSnapshots attaches this member's snapshot provider.
func (dashboard *Dashboard) SetSnapshots(source observability.SnapshotSource) {
	if source != nil {
		dashboard.snapshots.Store(&snapshotHolder{source: source})
	}
}

// SetCluster attaches the cell-wide provider.
func (dashboard *Dashboard) SetCluster(source observability.ClusterSource) {
	if source != nil {
		dashboard.cluster.Store(&clusterHolder{source: source})
	}
}

// Mount registers every page, its stream, the login form and the assets.
func (dashboard *Dashboard) Mount(mounter Mounter) {
	mounter.HandleStatic("GET /assets/{hash}/{file}", http.HandlerFunc(serveAsset))
	mounter.HandleLogin(dashboard.guard(http.HandlerFunc(dashboard.login)))
	for _, page := range pages {
		mounter.Handle("GET "+page.path(), dashboard.guard(dashboard.pageHandler(page)))
		mounter.Handle("GET "+page.streamPath(), dashboard.guard(dashboard.streamHandler(page)))
	}
}

// Handler returns the dashboard routes on their own mux without any
// authentication. Tests use it; production mounts on the private listener.
func (dashboard *Dashboard) Handler() http.Handler {
	mux := http.NewServeMux()
	dashboard.Mount(muxMounter{mux})
	return mux
}

type muxMounter struct{ mux *http.ServeMux }

func (mounter muxMounter) Handle(pattern string, handler http.Handler) {
	mounter.mux.Handle(pattern, handler)
}
func (mounter muxMounter) HandleStatic(pattern string, handler http.Handler) {
	mounter.mux.Handle(pattern, handler)
}
func (mounter muxMounter) HandleLogin(page http.Handler) { mounter.mux.Handle("GET /login", page) }

// contentSecurityPolicy allows only this listener's own files. Datastar
// evaluates its data-* expressions with Function, which needs unsafe-eval;
// there are no inline scripts or styles.
const contentSecurityPolicy = "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self'; " +
	"img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// guard applies the browser hardening headers and the Host check.
func (dashboard *Dashboard) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if dashboard.options.RequireLiteralHost && !literalHost(request.Host) {
			http.Error(writer, "the dashboard must be addressed by IP or localhost", http.StatusMisdirectedRequest)
			return
		}
		header := writer.Header()
		header.Set("Content-Security-Policy", contentSecurityPolicy)
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Cache-Control", "no-store")
		next.ServeHTTP(writer, request)
	})
}

func literalHost(host string) bool {
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	} else if len(host) > 1 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if host == "localhost" {
		return true
	}
	_, err := netip.ParseAddr(host)
	return err == nil
}

// load gathers the view every page renders from. Missing providers and
// failing sections become notes on the view, never a failed request.
func (dashboard *Dashboard) load(ctx context.Context, page page, filter eventFilter) view {
	current := view{Page: page, Now: dashboard.options.Now().UTC(), SignOut: dashboard.options.SignOut,
		Filter: filter}
	if health := dashboard.options.Health; health != nil {
		current.Ready, current.Checks = health.Evaluate(ctx)
	}
	if holder := dashboard.snapshots.Load(); holder != nil {
		snapshot, err := holder.source.Snapshot(ctx, false)
		if err != nil {
			current.Notes = append(current.Notes, "This member's snapshot is unavailable.")
		} else {
			current.Local = &snapshot
		}
	} else {
		current.Notes = append(current.Notes, "This member is still starting; its providers are not attached yet.")
	}
	if holder := dashboard.cluster.Load(); holder != nil {
		snapshot, err := dashboard.clusters.Get(ctx, func(ctx context.Context) (observability.ClusterSnapshot, error) {
			return holder.source.Cluster(ctx, false)
		})
		if err != nil {
			current.Notes = append(current.Notes, "The cell-wide view is unavailable; showing this member only.")
		} else {
			current.Cluster = &snapshot
		}
	}
	if page.events > 0 && dashboard.options.Events != nil {
		current.Events = filter.apply(dashboard.options.Events.Recent(0), page.events)
	}
	return current
}
