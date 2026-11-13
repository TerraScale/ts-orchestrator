package decisionlog

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ParseQuery reads a Query from URL parameters: region, kind, actor and
// status may repeat or hold comma-separated values; subject is a substring,
// subject_kind and subject_id match exactly; since and until are RFC 3339
// times or a duration back from now (for example since=1h); limit bounds
// the page.
func ParseQuery(values url.Values, now time.Time) (Query, error) {
	list := func(name string) []string {
		var out []string
		for _, value := range values[name] {
			for part := range strings.SplitSeq(value, ",") {
				if part = strings.TrimSpace(part); part != "" {
					out = append(out, part)
				}
			}
		}
		return out
	}
	query := Query{Regions: list("region"), Actors: list("actor"), Subject: values.Get("subject"),
		SubjectKind: values.Get("subject_kind"), SubjectID: values.Get("subject_id"), ParentID: values.Get("parent")}
	for _, kind := range list("kind") {
		query.Kinds = append(query.Kinds, Kind(kind))
	}
	for _, status := range list("status") {
		query.Statuses = append(query.Statuses, Status(status))
	}
	var err error
	if query.Since, err = parseTime(values.Get("since"), now); err != nil {
		return Query{}, errors.New("since must be an RFC 3339 time or a duration")
	}
	if query.Until, err = parseTime(values.Get("until"), now); err != nil {
		return Query{}, errors.New("until must be an RFC 3339 time or a duration")
	}
	if raw := values.Get("limit"); raw != "" {
		if query.Limit, err = strconv.Atoi(raw); err != nil || query.Limit < 0 {
			return Query{}, errors.New("limit must be a non-negative integer")
		}
	}
	return query.Normalized(), nil
}

func parseTime(raw string, now time.Time) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	if duration, err := time.ParseDuration(raw); err == nil {
		return now.Add(-duration.Abs()), nil
	}
	return time.Parse(time.RFC3339, raw)
}
