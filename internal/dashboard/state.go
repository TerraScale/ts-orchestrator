package dashboard

import (
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/a-h/templ"
)

// timeRange is one choice of the global time-range picker.
type timeRange struct {
	Key      string
	Duration time.Duration
}

var timeRanges = []timeRange{
	{Key: "15m", Duration: 15 * time.Minute},
	{Key: "1h", Duration: time.Hour},
	{Key: "6h", Duration: 6 * time.Hour},
	{Key: "24h", Duration: 24 * time.Hour},
}

const defaultRange = "1h"

// uiState is the URL-addressable state shared by every page: the time range,
// the selected region, whether the page streams live updates, and the
// page's own validated parameters. Every link the dashboard renders carries
// it, so any view can be bookmarked or shared and works without JavaScript.
type uiState struct {
	Range  timeRange
	Region string
	// Live is false when the operator paused auto-refresh (live=0).
	Live bool
	// Params holds the validated page parameters (id, kind, actor, ...).
	Params url.Values
}

// pageParams are the page-specific parameters a link may carry, with their
// validators. Anything else in a query string is ignored.
var pageParams = map[string]func(string) bool{
	"id":       validSearch,
	"host":     validToken,
	"db":       validToken,
	"volume":   validToken,
	"release":  validToken,
	"kind":     validList,
	"actor":    validList,
	"status":   validList,
	"severity": validList,
	"region":   validList,
	"q":        validSearch,
	"at":       validTime,
	"level":    func(value string) bool { return slices.Contains(levelNames, strings.ToLower(value)) },
	"component": func(value string) bool {
		return validComponent(value)
	},
}

func parseState(query url.Values) uiState {
	state := uiState{Range: timeRanges[1], Live: query.Get("live") != "0", Params: url.Values{}}
	for _, choice := range timeRanges {
		if choice.Key == query.Get("range") {
			state.Range = choice
		}
	}
	if region := strings.ToLower(query.Get("r")); validRegion(region) {
		state.Region = region
	}
	for name, valid := range pageParams {
		if value := strings.TrimSpace(query.Get(name)); value != "" && valid(value) {
			state.Params.Set(name, value)
		}
	}
	// subject= is what older insight entity links use for the journal's
	// subject or text filter.
	if subject := subjectSearch(strings.TrimSpace(query.Get("subject"))); subject != "" && !state.Params.Has("q") &&
		validSearch(subject) {
		state.Params.Set("q", subject)
	}
	return state
}

// subjectKinds are the decision subject kinds a kind-qualified subject link
// ("operation/op-123") may name.
var subjectKinds = []string{"release", "service", "host", "volume", "region", "member", "database", "seat",
	"operation", "intent", "peer", "cluster", "host_pool", "nats-meta"}

// subjectSearch turns a legacy subject= link value into the decision search
// text. The search matches subject IDs, names and summaries, never the
// kind-qualified form Subject.String() renders, so a known kind prefix is
// dropped.
func subjectSearch(subject string) string {
	if kind, id, found := strings.Cut(subject, "/"); found && id != "" && slices.Contains(subjectKinds, kind) {
		return id
	}
	return subject
}

func (state uiState) param(name string) string { return state.Params.Get(name) }

// allRegions is the region filter value that lists every region even when
// a region is selected in the top bar.
const allRegions = "all"

// regionFilter is the region filter of a page with its own region select
// (insights, decisions): the select's value, else the selected region,
// else none. "all" lists every region.
func (state uiState) regionFilter() []string {
	regions := state.list("region")
	if slices.Contains(regions, allRegions) {
		return nil
	}
	if len(regions) == 0 && state.Region != "" {
		return []string{state.Region}
	}
	return regions
}

// filtersRegion reports that the region filter selects exactly region.
func (state uiState) filtersRegion(region string) bool {
	regions := state.regionFilter()
	return len(regions) == 1 && regions[0] == region
}

// list splits a comma-separated parameter.
func (state uiState) list(name string) []string {
	var out []string
	for part := range strings.SplitSeq(state.Params.Get(name), ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// values returns the shared state as query values, without page parameters.
func (state uiState) values() url.Values {
	values := url.Values{}
	if state.Range.Key != defaultRange {
		values.Set("range", state.Range.Key)
	}
	if state.Region != "" {
		values.Set("r", state.Region)
	}
	if !state.Live {
		values.Set("live", "0")
	}
	return values
}

// query renders the shared state plus every page parameter.
func (state uiState) query() string {
	values := state.values()
	for name, value := range state.Params {
		values[name] = slices.Clone(value)
	}
	return values.Encode()
}

// link builds path with the shared state and the given name, value pairs.
// An empty value removes the parameter; "r" and "range" and "live" override
// the shared state.
func (state uiState) link(path string, pairs ...string) string {
	values := state.values()
	for index := 0; index+1 < len(pairs); index += 2 {
		if pairs[index+1] == "" {
			values.Del(pairs[index])
			continue
		}
		values.Set(pairs[index], pairs[index+1])
	}
	if encoded := values.Encode(); encoded != "" {
		return path + "?" + encoded
	}
	return path
}

// keep builds path with the shared state, every current page parameter and
// the given overrides; filter forms and pickers use it.
func (state uiState) keep(path string, pairs ...string) string {
	merged := make([]string, 0, len(state.Params)*2+len(pairs))
	for name := range state.Params {
		merged = append(merged, name, state.Params.Get(name))
	}
	return state.link(path, append(merged, pairs...)...)
}

// adopt adds the shared state to a dashboard link that may already carry a
// query, such as an insight's entity link. region is the region the entity
// lives in ("" for this member's region): it replaces the selected region,
// because the entity is in its own region whatever the page shows, unless
// the link names a region itself. Paths that providers still emit from
// before the dashboard pages existed are translated (/regions/<r> is
// /region?r=<r>, /regions is the global page, subject= is the journal's
// q=). A link that is not a local path is returned as "/" so a provider
// cannot point the page elsewhere.
func (state uiState) adopt(link, region string) string {
	parsed, err := url.Parse(link)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(parsed.Path, "/") ||
		strings.HasPrefix(parsed.Path, "//") {
		return "/"
	}
	values := parsed.Query()
	switch {
	case parsed.Path == "/regions" || parsed.Path == "/regions/":
		parsed.Path = "/"
	case strings.HasPrefix(parsed.Path, "/regions/") &&
		!strings.Contains(strings.TrimSuffix(strings.TrimPrefix(parsed.Path, "/regions/"), "/"), "/"):
		// /regions/<r> is the region overview; deeper paths such as
		// /regions/<r>/hosts/<h> are detail pages and kept as they are.
		if named := strings.ToLower(strings.TrimPrefix(parsed.Path, "/regions/")); validRegion(named) {
			values.Set("r", named)
		}
		parsed.Path = "/region"
	}
	if subject := values.Get("subject"); subject != "" {
		values.Del("subject")
		if !values.Has("q") {
			values.Set("q", subjectSearch(subject))
		}
	}
	for name, value := range state.values() {
		if name != "r" && !values.Has(name) {
			values[name] = value
		}
	}
	if region != "" && !values.Has("r") {
		values.Set("r", region)
	}
	parsed.RawQuery = values.Encode()
	return parsed.String()
}

// fields lists the shared state as sorted name, value pairs for hidden form
// inputs.
func (state uiState) fields() [][2]string {
	values := state.values()
	var out [][2]string
	for _, name := range slices.Sorted(maps.Keys(values)) {
		out = append(out, [2]string{name, values.Get(name)})
	}
	return out
}

func safe(link string) templ.SafeURL { return templ.SafeURL(link) }

func validRegion(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
			return false
		}
	}
	return true
}

// validToken accepts IDs, digests, OCIDs and host names.
func validToken(value string) bool {
	if len(value) > 160 {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' ||
			strings.ContainsRune("._-:/@", char)) {
			return false
		}
	}
	return true
}

func validList(value string) bool {
	if len(value) > 256 {
		return false
	}
	for part := range strings.SplitSeq(value, ",") {
		if !validToken(strings.TrimSpace(part)) {
			return false
		}
	}
	return true
}

func validSearch(value string) bool {
	if len(value) > 128 {
		return false
	}
	for _, char := range value {
		if char < ' ' || char == 0x7f {
			return false
		}
	}
	return true
}

func validTime(value string) bool {
	_, err := time.Parse(time.RFC3339, value)
	return err == nil
}
