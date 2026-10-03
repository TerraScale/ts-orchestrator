// Package regionview aggregates one region's state into the summary the
// global dashboard shows side by side for every region: a health score,
// controller quorum, the authority and NATS leaders, versions, capacity,
// TerraBase counts, active rollouts, the latest decisions and the open
// insights.
//
// The local region is summarized from the cell-wide observability snapshot,
// the decision journal and the insight engine. Other regions answer the same
// summary over ts.orch.v1.<region>.obs.region through regionlink; a region
// without a link is listed as not linked instead of being guessed at.
package regionview

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlink"
)

const (
	// SummaryLeaf is the observability subject leaf a region answers its
	// summary on.
	SummaryLeaf    = protocol.ObservabilityRegionLeaf
	summaryVersion = 1
	// DefaultLatestDecisions is how many decisions a summary carries.
	DefaultLatestDecisions = 5
	// DefaultTopInsights is how many insights a summary carries.
	DefaultTopInsights = 5
	// maxTopologyMembers and maxTopologyHosts bound the topology a summary
	// carries over the region link.
	maxTopologyMembers = 64
	maxTopologyHosts   = 256
	cacheTTL           = 3 * time.Second
	maxRequestBytes    = 256
)

// Status is a region's overall condition.
type Status string

const (
	StatusHealthy  Status = "healthy"
	StatusDegraded Status = "degraded"
	StatusCritical Status = "critical"
	// StatusUnknown is a region that cannot be observed.
	StatusUnknown Status = "unknown"
)

// Health is a 0-100 score with the reasons it was reduced.
type Health struct {
	Score   int      `json:"score"`
	Status  Status   `json:"status"`
	Reasons []string `json:"reasons,omitempty"`
}

// Quorum is the controller quorum state.
type Quorum struct {
	Expected  int  `json:"expected"`
	Answering int  `json:"answering"`
	Ready     int  `json:"ready"`
	Required  int  `json:"required"`
	Healthy   bool `json:"healthy"`
	// Missing lists expected controllers that did not answer.
	Missing []string `json:"missing,omitempty"`
	// Unobserved reports that the cell-wide view failed and only this
	// member answered: the controller roster and quorum are unknown.
	Unobserved bool `json:"unobserved,omitempty"`
}

// Leaders names the regional authority owner and the JetStream meta leader.
type Leaders struct {
	Authority  string `json:"authority,omitempty"`
	Epoch      uint64 `json:"epoch,omitzero"`
	MetaLeader string `json:"meta_leader,omitempty"`
}

// Version is one build and the members running it.
type Version struct {
	Version string   `json:"version"`
	Members []string `json:"members"`
}

// Capacity totals the members' resources.
type Capacity struct {
	CPUs            int     `json:"cpus"`
	CPUUtilization  float64 `json:"cpu_utilization,omitzero"`
	MemoryBytes     uint64  `json:"memory_bytes"`
	MemoryUsedBytes uint64  `json:"memory_used_bytes"`
	DiskBytes       uint64  `json:"disk_bytes"`
	DiskUsedBytes   uint64  `json:"disk_used_bytes"`
	StoreUsedBytes  uint64  `json:"store_used_bytes"`
	StoreLimitBytes int64   `json:"store_limit_bytes"`
}

// TerraBase counts managed databases and seats.
type TerraBase struct {
	Databases    int `json:"databases"`
	DesiredSeats int `json:"desired_seats"`
	ServingSeats int `json:"serving_seats"`
}

// Member is one answering member, for other regions' topology views.
type Member struct {
	Name    string `json:"name"`
	Role    string `json:"role,omitempty"`
	Ready   bool   `json:"ready"`
	Version string `json:"version,omitempty"`
	// MetaLeader marks the JetStream meta leader. The NATS meta leader name
	// is a server name, not a member name, so it is carried per member.
	MetaLeader bool `json:"meta_leader,omitempty"`
}

// Host is a host that carries TerraBase seats.
type Host struct {
	Name    string `json:"name"`
	Seats   int    `json:"seats"`
	Serving int    `json:"serving"`
}

// Summary is one region's card on the global view.
type Summary struct {
	Version int    `json:"version"`
	Region  string `json:"region"`
	Local   bool   `json:"local,omitzero"`
	// Reach is ok, not_linked, unreachable or error (decisionlog states).
	Reach      string                      `json:"reach"`
	ObservedAt time.Time                   `json:"observed_at,omitzero"`
	Health     Health                      `json:"health"`
	Quorum     Quorum                      `json:"quorum"`
	Leaders    Leaders                     `json:"leaders"`
	Versions   []Version                   `json:"versions,omitempty"`
	Capacity   Capacity                    `json:"capacity"`
	TerraBase  TerraBase                   `json:"terrabase"`
	Rollouts   []observability.RolloutView `json:"rollouts,omitempty"`
	Decisions  []decisionlog.Decision      `json:"decisions,omitempty"`
	Insights   []insights.Insight          `json:"insights,omitempty"`
	Counts     insights.Counts             `json:"counts"`
	// Members and Hosts are the region's answering members and seat hosts,
	// bounded, for the topology view. Older regions omit them.
	Members []Member `json:"members,omitempty"`
	Hosts   []Host   `json:"hosts,omitempty"`
}

// MixedVersions reports whether members run more than one build.
func (summary Summary) MixedVersions() bool { return len(summary.Versions) > 1 }

// Source is what the dashboard's global and region pages read. Provider
// implements it.
type Source interface {
	// Regions returns every configured region, local first.
	Regions(ctx context.Context) []Summary
	// Region returns one region's summary.
	Region(ctx context.Context, region string) (Summary, error)
}

// Provider builds the local summary and gathers the others.
type Provider struct {
	// Cell is the local region token.
	Cell      string
	Cluster   observability.ClusterSource
	Snapshot  observability.SnapshotSource
	History   observability.HistorySource
	Decisions decisionlog.Source
	Insights  insights.Source
	Links     regionlink.Requester
	// LatestDecisions and TopInsights bound the lists; zero takes the
	// defaults.
	LatestDecisions int
	TopInsights     int
	Now             func() time.Time

	once    sync.Once
	cache   observability.Cache[[]Summary]
	reachMu sync.Mutex
	seen    map[string]time.Time
}

func (provider *Provider) now() time.Time {
	if provider.Now != nil {
		return provider.Now().UTC()
	}
	return time.Now().UTC()
}

// Local summarizes this region.
func (provider *Provider) Local(ctx context.Context) Summary {
	region := strings.ToLower(provider.Cell)
	summary := Summary{Version: summaryVersion, Region: region, Local: true, Reach: decisionlog.RegionOK,
		ObservedAt: provider.now()}
	var cluster *observability.ClusterSnapshot
	if provider.Cluster != nil {
		if snapshot, err := provider.Cluster.Cluster(ctx, false); err == nil {
			cluster = &snapshot
		}
	}
	unobserved := false
	if cluster == nil && provider.Snapshot != nil {
		if snapshot, err := provider.Snapshot.Snapshot(ctx, false); err == nil {
			cluster = &observability.ClusterSnapshot{Cell: snapshot.Cell, Members: []observability.MemberSnapshot{snapshot}}
			// Without a cluster source this member is the whole cell; with
			// one that failed, the rest of the roster is unknown.
			unobserved = provider.Cluster != nil
		}
	}
	if cluster != nil {
		fillFromCluster(&summary, *cluster)
		if unobserved {
			summary.Quorum = Quorum{Answering: summary.Quorum.Answering, Ready: summary.Quorum.Ready, Unobserved: true}
		}
	}
	if provider.History != nil {
		var sum float64
		var count int
		for _, value := range latest(provider.History, observability.HistCPUUtilization) {
			sum += value
			count++
		}
		if count > 0 {
			summary.Capacity.CPUUtilization = sum / float64(count)
		}
	}
	if provider.Decisions != nil {
		limit := cmp.Or(provider.LatestDecisions, DefaultLatestDecisions)
		if result, err := provider.Decisions.Query(ctx, decisionlog.Query{Regions: []string{region}, Limit: limit}); err == nil {
			summary.Decisions = result.Decisions
		}
	}
	var open []insights.Insight
	if provider.Insights != nil {
		// The engine also raises insights about other regions (one that
		// does not answer); they belong to the global view, not this
		// region's counts and score.
		for _, insight := range provider.Insights.Current().Insights {
			if insight.Region == "" || strings.EqualFold(insight.Region, region) {
				open = append(open, insight)
			}
		}
		summary.Counts = insights.Count(open)
		summary.Insights = open[:min(len(open), cmp.Or(provider.TopInsights, DefaultTopInsights))]
	}
	summary.Health = score(summary, cluster != nil, open)
	return summary
}

func latest(history observability.HistorySource, metric string) map[string]float64 {
	type latestSource interface {
		Latest(string, map[string]string) map[string]float64
	}
	if source, ok := history.(latestSource); ok {
		return source.Latest(metric, nil)
	}
	return nil
}

func fillFromCluster(summary *Summary, cluster observability.ClusterSnapshot) {
	quorum := &summary.Quorum
	quorum.Expected = len(cluster.Expected)
	if quorum.Expected == 0 {
		quorum.Expected = len(cluster.Members) + len(cluster.Missing)
	}
	quorum.Answering = len(cluster.Members)
	quorum.Required = quorum.Expected/2 + 1
	quorum.Missing = slices.Clone(cluster.Missing)
	versions := map[string][]string{}
	for _, member := range cluster.Members {
		if member.Ready {
			quorum.Ready++
		}
		if len(summary.Members) < maxTopologyMembers {
			summary.Members = append(summary.Members, Member{Name: member.Member, Role: member.Role, Ready: member.Ready,
				Version: member.BuildVersion, MetaLeader: member.NATS != nil && member.NATS.IsMetaLeader})
		}
		if member.BuildVersion != "" {
			versions[member.BuildVersion] = append(versions[member.BuildVersion], member.Member)
		}
		// The owner is the newest valid lease any member observes, whatever
		// the member order; the holder's own report wins a tie. A member
		// that observes no ready lease (control-log failures keep its own
		// candidate as OwnerID) is no evidence of a leader.
		if authority := member.Authority; authority != nil && authority.Ready && authority.Epoch > 0 &&
			(authority.Leader || authority.OwnerID != "") {
			owner := authority.OwnerID
			if authority.Leader {
				owner = member.Member
			}
			if authority.Epoch > summary.Leaders.Epoch || authority.Epoch == summary.Leaders.Epoch && authority.Leader {
				summary.Leaders.Authority, summary.Leaders.Epoch = owner, authority.Epoch
			}
		}
		if nats := member.NATS; nats != nil {
			if nats.MetaLeader != "" {
				summary.Leaders.MetaLeader = nats.MetaLeader
			}
			summary.Capacity.StoreUsedBytes += nats.StoreUsedBytes
			summary.Capacity.StoreLimitBytes += nats.StoreLimitBytes
		}
		if system := member.System; system != nil {
			summary.Capacity.CPUs += system.CPUCount
			summary.Capacity.MemoryBytes += system.MemTotalBytes
			summary.Capacity.MemoryUsedBytes += system.MemTotalBytes - min(system.MemAvailBytes, system.MemTotalBytes)
			for _, filesystem := range observability.DistinctFilesystems(system.Filesystems) {
				summary.Capacity.DiskBytes += filesystem.SizeBytes
				summary.Capacity.DiskUsedBytes += filesystem.SizeBytes - min(filesystem.AvailBytes, filesystem.SizeBytes)
			}
		}
	}
	quorum.Healthy = quorum.Answering >= quorum.Required
	for _, version := range slices.Sorted(maps.Keys(versions)) {
		members := versions[version]
		slices.Sort(members)
		summary.Versions = append(summary.Versions, Version{Version: version, Members: members})
	}
	var placement *observability.PlacementView
	for _, member := range cluster.Members {
		if member.Placement != nil && (placement == nil || len(member.Placement.Databases) > len(placement.Databases)) {
			placement = member.Placement
		}
	}
	slices.SortFunc(summary.Members, func(left, right Member) int { return strings.Compare(left.Name, right.Name) })
	if placement != nil {
		// Placement lists one entry per database partition.
		databases := map[string]bool{}
		for _, database := range placement.Databases {
			databases[database.DatabaseID] = true
		}
		summary.TerraBase.Databases = len(databases)
		hosts := map[string]*Host{}
		for _, database := range placement.Databases {
			for _, seat := range database.Members {
				if seat.HostNode == "" {
					continue
				}
				host := hosts[seat.HostNode]
				if host == nil {
					host = &Host{Name: seat.HostNode}
					hosts[seat.HostNode] = host
				}
				host.Seats++
				if seat.Stage == "serving" {
					host.Serving++
				}
			}
			summary.TerraBase.DesiredSeats += database.DesiredSeats
			summary.TerraBase.ServingSeats += database.Serving
			if rollout := database.Rollout; rollout != nil && rollout.Completed < rollout.Seats {
				summary.Rollouts = append(summary.Rollouts, *rollout)
			}
		}
		for _, name := range slices.Sorted(maps.Keys(hosts)) {
			if len(summary.Hosts) == maxTopologyHosts {
				break
			}
			summary.Hosts = append(summary.Hosts, *hosts[name])
		}
	}
}

// Rules whose problem the score already counts from the snapshot.
var scoredDirectly = map[string]bool{"quorum_at_risk": true, "no_leader": true, "member_not_ready": true}

// score derives a deterministic health score. Quorum, leadership and
// readiness come from the snapshot; other open insights subtract by
// severity, each severity capped so one noisy rule cannot zero a region.
func score(summary Summary, observed bool, open []insights.Insight) Health {
	if !observed || summary.Quorum.Answering == 0 {
		return Health{Score: 0, Status: StatusUnknown, Reasons: []string{"no member state observed"}}
	}
	value := 100
	var reasons []string
	penalize := func(points int, reason string) {
		value -= points
		reasons = append(reasons, reason)
	}
	quorum := summary.Quorum
	if quorum.Unobserved {
		penalize(30, "controller quorum not observed (the cell-wide view failed)")
	}
	if missing := quorum.Expected - quorum.Answering; missing > 0 {
		if !quorum.Healthy {
			penalize(60, fmt.Sprintf("controller quorum lost (%d of %d answering)", quorum.Answering, quorum.Expected))
		} else {
			penalize(15*missing, fmt.Sprintf("%d of %d controllers missing", missing, quorum.Expected))
		}
	}
	if notReady := quorum.Answering - quorum.Ready; notReady > 0 {
		penalize(min(10*notReady, 30), fmt.Sprintf("%d members not ready", notReady))
	}
	if summary.Leaders.Authority == "" {
		penalize(40, "no authority leader")
	}
	var critical, warning, info int
	for _, insight := range open {
		if scoredDirectly[insight.Rule] {
			continue
		}
		switch insight.Severity {
		case insights.SeverityCritical:
			critical++
		case insights.SeverityWarning:
			warning++
		default:
			info++
		}
	}
	if critical > 0 {
		penalize(min(25*critical, 50), fmt.Sprintf("%d critical problems", critical))
	}
	if warning > 0 {
		penalize(min(8*warning, 24), fmt.Sprintf("%d warnings", warning))
	}
	if info > 0 {
		penalize(min(2*info, 6), fmt.Sprintf("%d notes", info))
	}
	if len(summary.Versions) > 1 {
		penalize(5, "mixed versions")
	}
	value = max(value, 0)
	status := StatusHealthy
	switch {
	case value < 50:
		status = StatusCritical
	case value < 85:
		status = StatusDegraded
	}
	return Health{Score: value, Status: status, Reasons: reasons}
}

// Regions returns every configured region's summary, local first. Remote
// summaries are fetched in parallel; the result is cached for a few seconds
// so several dashboard streams share one round of requests.
func (provider *Provider) Regions(ctx context.Context) []Summary {
	provider.once.Do(func() { provider.cache.TTL = cacheTTL })
	summaries, _ := provider.cache.Get(ctx, func(ctx context.Context) ([]Summary, error) {
		return provider.gather(ctx), nil
	})
	return slices.Clone(summaries)
}

func (provider *Provider) gather(ctx context.Context) []Summary {
	local := strings.ToLower(provider.Cell)
	regions := []string{local}
	if provider.Links != nil {
		regions = provider.Links.Regions()
	}
	summaries := make([]Summary, len(regions))
	var group sync.WaitGroup
	for index, region := range regions {
		group.Go(func() {
			if region == local {
				summaries[index] = provider.Local(ctx)
				return
			}
			summaries[index] = provider.remote(ctx, region)
		})
	}
	group.Wait()
	provider.reachMu.Lock()
	defer provider.reachMu.Unlock()
	if provider.seen == nil {
		provider.seen = map[string]time.Time{}
	}
	for _, summary := range summaries {
		if summary.Reach == decisionlog.RegionOK {
			provider.seen[summary.Region] = provider.now()
		}
	}
	return summaries
}

func (provider *Provider) remote(ctx context.Context, region string) Summary {
	placeholder := Summary{Version: summaryVersion, Region: region,
		Health: Health{Status: StatusUnknown, Reasons: []string{"region not observed"}}}
	if provider.Links == nil {
		placeholder.Reach = decisionlog.RegionNotLinked
		return placeholder
	}
	data, err := provider.Links.Request(ctx, region, SummaryLeaf, []byte(`{"version":1}`))
	if err != nil {
		switch {
		case errors.Is(err, regionlink.ErrNotLinked):
			placeholder.Reach = decisionlog.RegionNotLinked
			placeholder.Health.Reasons = []string{"no cross-region link yet"}
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, nats.ErrTimeout), errors.Is(err, nats.ErrNoResponders):
			placeholder.Reach = decisionlog.RegionUnreachable
			placeholder.Health.Reasons = []string{"region did not answer"}
		default:
			placeholder.Reach = decisionlog.RegionError
			placeholder.Health.Reasons = []string{"region query failed"}
		}
		return placeholder
	}
	var summary Summary
	if err := json.Unmarshal(data, &summary); err != nil || summary.Version != summaryVersion || summary.Region != region {
		placeholder.Reach = decisionlog.RegionError
		placeholder.Health.Reasons = []string{"region returned an invalid summary"}
		return placeholder
	}
	summary.Local = false
	summary.Reach = decisionlog.RegionOK
	summary.boundTopology()
	// Never trust a region to speak for another one.
	summary.Decisions = slices.DeleteFunc(summary.Decisions, func(decision decisionlog.Decision) bool {
		return decision.Region != region
	})
	return summary
}

// boundTopology caps the lists another region controls before the
// dashboard draws them: the topology meshes every controller pair, so an
// unbounded member or missing list from a peer would cost quadratic work on
// every stream tick.
func (summary *Summary) boundTopology() {
	summary.Members = summary.Members[:min(len(summary.Members), maxTopologyMembers)]
	summary.Hosts = summary.Hosts[:min(len(summary.Hosts), maxTopologyHosts)]
	summary.Quorum.Missing = summary.Quorum.Missing[:min(len(summary.Quorum.Missing), maxTopologyMembers)]
	summary.Versions = summary.Versions[:min(len(summary.Versions), maxTopologyMembers)]
	for index := range summary.Versions {
		members := summary.Versions[index].Members
		summary.Versions[index].Members = members[:min(len(members), maxTopologyMembers)]
	}
}

// Region returns one region's summary.
func (provider *Provider) Region(ctx context.Context, region string) (Summary, error) {
	region = strings.ToLower(region)
	for _, summary := range provider.Regions(ctx) {
		if summary.Region == region {
			return summary, nil
		}
	}
	return Summary{}, regionlink.ErrUnknownRegion
}

// Reachability reports each remote region's reach for the insight engine.
func (provider *Provider) Reachability(ctx context.Context) []insights.RegionReach {
	var out []insights.RegionReach
	summaries := provider.Regions(ctx)
	provider.reachMu.Lock()
	defer provider.reachMu.Unlock()
	for _, summary := range summaries {
		if summary.Local {
			continue
		}
		out = append(out, insights.RegionReach{Region: summary.Region, State: summary.Reach,
			LastSeen: provider.seen[summary.Region]})
	}
	return out
}

// Serve answers summary requests for cell with provider's local summary.
// Every controller subscribes in one queue group, so one answers.
func Serve(ctx context.Context, conn *nats.Conn, cell string, provider *Provider) (*nats.Subscription, error) {
	if conn == nil || provider == nil {
		return nil, errors.New("region summary responder requires a connection and a provider")
	}
	subject, err := protocol.ObservabilitySubject(cell, SummaryLeaf)
	if err != nil {
		return nil, err
	}
	subscription, err := conn.QueueSubscribe(subject, "regionview", func(message *nats.Msg) {
		// Peer regions reach this subject over the interregion contract, so
		// only the exact versioned summary request is answered.
		if message.Reply == "" || !validSummaryRequest(message.Data) {
			return
		}
		answerCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		data, err := json.Marshal(provider.Local(answerCtx))
		if err != nil || int64(len(data)) > conn.MaxPayload() {
			return
		}
		_ = message.Respond(data)
	})
	if err != nil {
		return nil, err
	}
	context.AfterFunc(ctx, func() { _ = subscription.Unsubscribe() })
	return subscription, nil
}

// summaryRequest is the only request body the summary responder accepts.
type summaryRequest struct {
	Version int `json:"version"`
}

func validSummaryRequest(data []byte) bool {
	var request summaryRequest
	return len(data) <= maxRequestBytes && protocol.DecodeStrict(data, &request, maxRequestBytes) == nil &&
		request.Version == summaryVersion
}

var (
	_ Source                        = (*Provider)(nil)
	_ insights.ReachabilityProvider = (*Provider)(nil)
)
