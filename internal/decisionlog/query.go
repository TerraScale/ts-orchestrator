package decisionlog

import (
	"cmp"
	"slices"
	"strings"
	"time"
)

const (
	// DefaultQueryLimit is the page size of a query without a limit.
	DefaultQueryLimit = 100
	// MaxQueryLimit bounds one query, local or remote.
	MaxQueryLimit = 1000
)

// Query selects decisions. Empty fields match everything; list fields match
// any listed value. Results are newest first.
type Query struct {
	Regions []string `json:"regions,omitempty"`
	Kinds   []Kind   `json:"kinds,omitempty"`
	// Actors match Actor.Slice, or "slice/member" for one member.
	Actors []string `json:"actors,omitempty"`
	// SubjectKind and SubjectID match exactly; Subject matches a substring
	// of the subject ID, name or the summary, case-insensitively.
	SubjectKind string   `json:"subject_kind,omitempty"`
	SubjectID   string   `json:"subject_id,omitempty"`
	Subject     string   `json:"subject,omitempty"`
	Statuses    []Status `json:"statuses,omitempty"`
	ParentID    string   `json:"parent_id,omitempty"`
	// Since is inclusive and Until exclusive; zero values are unbounded.
	Since time.Time `json:"since,omitzero"`
	Until time.Time `json:"until,omitzero"`
	Limit int       `json:"limit,omitzero"`
}

// Normalized returns the query with its limit bounded and its region and
// subject filters lowercased.
func (query Query) Normalized() Query {
	if query.Limit <= 0 {
		query.Limit = DefaultQueryLimit
	}
	query.Limit = min(query.Limit, MaxQueryLimit)
	query.Regions = slices.Clone(query.Regions)
	for index, region := range query.Regions {
		query.Regions[index] = strings.ToLower(region)
	}
	query.Subject = strings.ToLower(query.Subject)
	return query
}

// Matches reports whether a decision satisfies every filter of a normalized
// query.
func (query Query) Matches(decision Decision) bool {
	if len(query.Regions) > 0 && !slices.Contains(query.Regions, decision.Region) {
		return false
	}
	if len(query.Kinds) > 0 && !slices.Contains(query.Kinds, decision.Kind) {
		return false
	}
	if len(query.Actors) > 0 && !slices.ContainsFunc(query.Actors, func(actor string) bool {
		return actor == decision.Actor.Slice || actor == decision.Actor.Slice+"/"+decision.Actor.Member
	}) {
		return false
	}
	if query.SubjectKind != "" && query.SubjectKind != decision.Subject.Kind {
		return false
	}
	if query.SubjectID != "" && query.SubjectID != decision.Subject.ID {
		return false
	}
	if query.Subject != "" && !containsFold(decision.Subject.ID, query.Subject) &&
		!containsFold(decision.Subject.Name, query.Subject) && !containsFold(decision.Summary, query.Subject) {
		return false
	}
	if len(query.Statuses) > 0 && !slices.Contains(query.Statuses, decision.Status) {
		return false
	}
	if query.ParentID != "" && query.ParentID != decision.ParentID {
		return false
	}
	if !query.Since.IsZero() && decision.Time.Before(query.Since) {
		return false
	}
	if !query.Until.IsZero() && !decision.Time.Before(query.Until) {
		return false
	}
	return true
}

func containsFold(value, lowerNeedle string) bool {
	return value != "" && strings.Contains(strings.ToLower(value), lowerNeedle)
}

// SortNewestFirst orders decisions by time, newest first, breaking ties by
// ID so merged regional results are stable.
func SortNewestFirst(decisions []Decision) {
	slices.SortStableFunc(decisions, func(left, right Decision) int {
		if order := right.Time.Compare(left.Time); order != 0 {
			return order
		}
		return cmp.Compare(right.ID, left.ID)
	})
}

// Result is one page of decisions and how complete it is.
type Result struct {
	Decisions []Decision `json:"decisions"`
	// Truncated reports that more decisions matched than Limit.
	Truncated bool `json:"truncated,omitzero"`
	// Partial reports that part of the requested range was not searched,
	// for example because it is older than the in-memory window and the
	// durable stream was unavailable.
	Partial bool `json:"partial,omitzero"`
	// Regions reports per-region status for a cross-region query.
	Regions []RegionStatus `json:"regions,omitempty"`
}

// RegionStatus is one region's answer to a cross-region query.
type RegionStatus struct {
	Region string `json:"region"`
	// State is ok, unreachable, error or not_linked.
	State string `json:"state"`
	Count int    `json:"count"`
	// Detail is a short fixed phrase, never upstream error text.
	Detail string `json:"detail,omitempty"`
}

// Region states reported in RegionStatus.
const (
	RegionOK          = "ok"
	RegionUnreachable = "unreachable"
	RegionError       = "error"
	RegionNotLinked   = "not_linked"
)

// Chain is a decision with its ancestors and descendants, oldest first.
type Chain struct {
	Root      Decision   `json:"root"`
	Decisions []Decision `json:"decisions"`
	// Latest is the newest decision in the chain; its status is the
	// chain's current status.
	Latest Decision `json:"latest"`
}

// BuildChain assembles the chain containing id from a set of decisions. It
// follows ParentID upward to the root and then collects every descendant of
// the root. ok is false when id is not in the set.
func BuildChain(decisions []Decision, id string) (Chain, bool) {
	byID := make(map[string]Decision, len(decisions))
	children := map[string][]string{}
	for _, decision := range decisions {
		byID[decision.ID] = decision
		if decision.ParentID != "" {
			children[decision.ParentID] = append(children[decision.ParentID], decision.ID)
		}
	}
	current, ok := byID[id]
	if !ok {
		return Chain{}, false
	}
	seen := map[string]bool{current.ID: true}
	for current.ParentID != "" {
		parent, found := byID[current.ParentID]
		if !found || seen[parent.ID] {
			break
		}
		seen[parent.ID] = true
		current = parent
	}
	chain := Chain{Root: current}
	visited := map[string]bool{}
	queue := []string{current.ID}
	for len(queue) > 0 && len(chain.Decisions) < MaxQueryLimit {
		next := queue[0]
		queue = queue[1:]
		if visited[next] {
			continue
		}
		visited[next] = true
		chain.Decisions = append(chain.Decisions, byID[next])
		queue = append(queue, children[next]...)
	}
	slices.SortStableFunc(chain.Decisions, func(left, right Decision) int {
		if order := left.Time.Compare(right.Time); order != 0 {
			return order
		}
		return cmp.Compare(left.ID, right.ID)
	})
	chain.Latest = chain.Decisions[len(chain.Decisions)-1]
	return chain, true
}
