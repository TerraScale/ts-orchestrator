package insights

import (
	"fmt"
	"strings"
	"time"
)

const maxOCIErrorText = 160

// ociDrift raises one insight per desired OCI resource that is foreign,
// failing, or out of sync for longer than the OCIDrift threshold. Drift on
// a report-only resource is expected until an operator acts, so it is info;
// drift that an enforcing reconcile does not clear is a warning.
//
// Observations are read from a persistent bucket and the reconcile may run
// rarely or not at all (no ready leader), so re-reading one observation is
// not evidence that a condition persists. A failure or drift fires only
// once a pass observed it again after the condition was first seen, and an
// observation older than OCIStale is treated as unknown.
func ociDrift(inputs *Inputs) []Insight {
	var out []Insight
	var stale []string
	for _, resource := range inputs.OCIResources {
		if resource.ObservedAt.IsZero() || inputs.Now.Sub(resource.ObservedAt) > inputs.Thresholds.OCIStale {
			stale = append(stale, resource.Key)
			continue
		}
		entity := Entity{Kind: "oci-resource", ID: resource.Key, Href: "/insights"}
		inspect := Action{Label: "Inspect the observed state",
			Command: "nats kv get TS_OCI_OBSERVED " + strings.ReplaceAll(resource.Key, "/", ".")}
		switch {
		case resource.Foreign:
			out = append(out, Insight{Severity: SeverityWarning, Score: 1, Key: "oci_drift:foreign:" + resource.Key,
				Title: "OCI resource " + resource.Key + " is not owned by this controller",
				Why: "The cloud object exists but lacks this controller's ownership tags, so the reconcile leaves it " +
					"alone and its desired spec is not applied.",
				Entity: entity,
				Actions: []Action{{Label: "Tag the object with the controller's ownership after review",
					Href: "/insights"}, inspect}})
		case resource.Error != "":
			held, ok := persisted(inputs, "oci_drift:error:"+resource.Key, resource.ObservedAt)
			if !ok {
				continue
			}
			out = append(out, Insight{Severity: SeverityWarning, Score: held.Seconds(), Key: "oci_drift:error:" + resource.Key,
				Title:  "OCI reconcile of " + resource.Key + " keeps failing",
				Why:    fmt.Sprintf("Every pass for %s has failed; the last error is shown below.", roundDuration(held)),
				Entity: entity,
				Evidence: []Evidence{{Label: "Last error", Text: truncate(resource.Error, maxOCIErrorText)},
					{Label: "Failing for", Value: held.Seconds(), Unit: "s", Comparison: "<",
						Threshold: threshold(inputs.Thresholds.OCIDrift.Seconds())}},
				Actions: []Action{inspect}})
		case !resource.InSync && !resource.Applied:
			held, ok := persisted(inputs, "oci_drift:drift:"+resource.Key, resource.ObservedAt)
			if !ok {
				continue
			}
			severity, why := SeverityWarning,
				fmt.Sprintf("The enforcing reconcile has not converged %s for %s.", resource.Key, roundDuration(held))
			if resource.Policy != "enforce" {
				severity, why = SeverityInfo,
					fmt.Sprintf("%s differs from its desired spec. Its policy is report-only, so nothing is changed "+
						"until an operator switches it to enforce or corrects the cloud object.", resource.Key)
			}
			out = append(out, Insight{Severity: severity, Score: float64(len(resource.Drift)), Key: "oci_drift:drift:" + resource.Key,
				Title:  fmt.Sprintf("OCI resource %s has %d pending changes", resource.Key, len(resource.Drift)),
				Why:    why,
				Entity: entity,
				Evidence: []Evidence{{Label: "Pending changes", Value: float64(len(resource.Drift)),
					Text: truncate(strings.Join(resource.Drift, "; "), 2*maxOCIErrorText), Comparison: "<=", Threshold: threshold(0)}},
				Actions: []Action{inspect}})
		}
	}
	if len(stale) > 0 {
		// Unknown is not healthy: say that the reconcile stopped observing
		// instead of letting its earlier problems silently resolve.
		out = append(out, Insight{Severity: SeverityInfo, Score: float64(len(stale)), Key: "oci_drift:stale",
			Title: fmt.Sprintf("%d OCI reconcile observations are stale", len(stale)),
			Why: fmt.Sprintf("No reconcile pass observed %s within %s; the regional leader may not be running "+
				"the OCI reconcile.", truncate(strings.Join(stale, ", "), 2*maxOCIErrorText),
				roundDuration(inputs.Thresholds.OCIStale)),
			Entity:  Entity{Kind: "oci-resource", ID: "stale", Href: "/insights"},
			Actions: []Action{{Label: "Check the authority leader and its OCI reconcile logs", Href: "/members"}}})
	}
	return out
}

// persisted reports how long condition has held and whether it counts: it
// must have held for OCIDrift and been observed again by a pass that ran
// after the condition was first seen.
func persisted(inputs *Inputs, condition string, observedAt time.Time) (time.Duration, bool) {
	held := inputs.Since(condition)
	return held, held >= inputs.Thresholds.OCIDrift && observedAt.After(inputs.Now.Add(-held))
}

func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	cut := limit
	for cut > 0 && cut < len(text) && text[cut]&0xC0 == 0x80 {
		cut--
	}
	return text[:cut] + "…"
}
