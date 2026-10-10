package insights

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

// SummaryInput is everything a summary is generated from.
type SummaryInput struct {
	Now    time.Time
	Window time.Duration
	// Scope names what is summarized, for example "GRU" or "all regions".
	Scope     string
	Decisions []decisionlog.Decision
	// DecisionsTruncated reports that more decisions matched the window
	// than Decisions holds, so counts are lower bounds.
	DecisionsTruncated bool
	// DecisionsPartial reports that part of the window could not be
	// searched; Unanswered names the regions that did not answer.
	DecisionsPartial bool
	Unanswered       []string
	Changes          []Change
	// ChangesTruncated reports that the insight engine no longer holds
	// every change of the window, so opened/resolved counts are lower
	// bounds.
	ChangesTruncated bool
	Open             []Insight
	// AttentionScope names what Open covers when it is narrower than
	// Scope, for example this region's engine in an all-regions summary.
	AttentionScope string
}

// Summary is a deterministic plain-language account of a window.
type Summary struct {
	Window    time.Duration `json:"window"`
	Scope     string        `json:"scope"`
	Generated time.Time     `json:"generated"`
	// Text is one paragraph.
	Text string `json:"text"`
	// Sentences are Text's parts, for a list rendering.
	Sentences []string `json:"sentences"`
	Decisions int      `json:"decisions"`
	Opened    int      `json:"opened"`
	Resolved  int      `json:"resolved"`
	Open      Counts   `json:"open"`
	// Partial reports that the counts cover only part of the window or
	// scope.
	Partial bool `json:"partial,omitzero"`
}

// kindNouns maps decision kinds to singular and plural phrases.
var kindNouns = map[decisionlog.Kind][2]string{
	decisionlog.KindReleaseAdmitted:    {"release admitted", "releases admitted"},
	decisionlog.KindUpgradeStarted:     {"upgrade started", "upgrades started"},
	decisionlog.KindCanaryPromoted:     {"canary promoted", "canaries promoted"},
	decisionlog.KindBatchPromoted:      {"batch promoted", "batches promoted"},
	decisionlog.KindRolloutCompleted:   {"rollout completed", "rollouts completed"},
	decisionlog.KindRollback:           {"rollback", "rollbacks"},
	decisionlog.KindHeld:               {"hold", "holds"},
	decisionlog.KindHoldCleared:        {"hold cleared", "holds cleared"},
	decisionlog.KindFrozen:             {"freeze", "freezes"},
	decisionlog.KindScaleUp:            {"scale-up", "scale-ups"},
	decisionlog.KindScaleDown:          {"scale-down", "scale-downs"},
	decisionlog.KindHostLaunched:       {"host launch", "host launches"},
	decisionlog.KindHostReclaimed:      {"host reclaimed", "hosts reclaimed"},
	decisionlog.KindMemberReplaced:     {"member replacement", "member replacements"},
	decisionlog.KindControllerReplaced: {"controller replacement", "controller replacements"},
	decisionlog.KindStageChanged:       {"seat stage change", "seat stage changes"},
	decisionlog.KindVolumeResized:      {"volume resize", "volume resizes"},
	decisionlog.KindVolumeReattached:   {"volume reattachment", "volume reattachments"},
	decisionlog.KindBackupTaken:        {"backup", "backups"},
	decisionlog.KindRegionProposed:     {"region proposal", "region proposals"},
	decisionlog.KindRegionApproved:     {"region approval", "region approvals"},
	decisionlog.KindRegionAdmitted:     {"region admission", "region admissions"},
	decisionlog.KindRegionStep:         {"region step", "region steps"},
	decisionlog.KindLeaderChanged:      {"leader change", "leader changes"},
	decisionlog.KindQuorumDegraded:     {"quorum loss", "quorum losses"},
	decisionlog.KindQuorumRestored:     {"quorum recovery", "quorum recoveries"},
	decisionlog.KindDeliveryApplied:    {"delivery applied", "deliveries applied"},
	decisionlog.KindDeliveryHeld:       {"delivery held", "deliveries held"},
	decisionlog.KindDeliveryRejected:   {"delivery rejected", "deliveries rejected"},
	decisionlog.KindFounderLaunched:    {"founder launch", "founder launches"},
	decisionlog.KindPeerEnrolled:       {"peer enrollment", "peer enrollments"},

	// OCI declarative reconcile.
	decisionlog.KindOCIDesiredPublished: {"OCI desired spec published", "OCI desired specs published"},
	decisionlog.KindOCIDriftCorrected:   {"OCI drift correction", "OCI drift corrections"},
	decisionlog.KindOCIResourceDeleted:  {"OCI resource deletion", "OCI resource deletions"},
	decisionlog.KindOCIResourceReleased: {"OCI resource released", "OCI resources released"},
}

// KindPhrase returns "1 hold" or "3 holds" for a kind and count.
func KindPhrase(kind decisionlog.Kind, count int) string {
	nouns, ok := kindNouns[kind]
	if !ok {
		name := strings.ReplaceAll(string(kind), "_", " ")
		nouns = [2]string{name, name}
		if count != 1 {
			return fmt.Sprintf("%d %s decisions", count, name)
		}
		return fmt.Sprintf("1 %s decision", name)
	}
	if count == 1 {
		return "1 " + nouns[0]
	}
	return fmt.Sprintf("%d %s", count, nouns[1])
}

// WindowPhrase renders a window as "hour", "24 hours" or "15 minutes".
func WindowPhrase(window time.Duration) string {
	switch {
	case window == time.Hour:
		return "hour"
	case window%time.Hour == 0:
		return fmt.Sprintf("%d hours", int(window.Hours()))
	case window%time.Minute == 0:
		return fmt.Sprintf("%d minutes", int(window.Minutes()))
	default:
		return window.String()
	}
}

// Summarize writes the paragraph. The same input always yields the same
// text: kinds are ordered by count then name, and only data inside the
// window is used.
func Summarize(input SummaryInput) Summary {
	since := input.Now.Add(-input.Window)
	scope := input.Scope
	if scope == "" {
		scope = "the region"
	}
	summary := Summary{Window: input.Window, Scope: scope, Generated: input.Now, Open: Count(input.Open)}
	var decisions []decisionlog.Decision
	for _, decision := range input.Decisions {
		if !decision.Time.Before(since) && !decision.Time.After(input.Now) {
			decisions = append(decisions, decision)
		}
	}
	decisionlog.SortNewestFirst(decisions)
	summary.Decisions = len(decisions)
	window := WindowPhrase(input.Window)
	var sentences []string
	// A truncated decision query makes the count a lower bound, which a
	// structured consumer must be able to tell apart from an exact count.
	summary.Partial = input.DecisionsTruncated || input.DecisionsPartial || input.ChangesTruncated
	switch {
	case len(decisions) == 0 && input.DecisionsPartial:
		sentences = append(sentences, fmt.Sprintf("In the last %s no decisions were found in %s, but part of the "+
			"history could not be searched%s.", window, scope, unansweredText(input.Unanswered)))
	case len(decisions) == 0:
		sentences = append(sentences, fmt.Sprintf("In the last %s the orchestrator made no recorded decisions in %s.",
			window, scope))
	default:
		counts := map[decisionlog.Kind]int{}
		for _, decision := range decisions {
			counts[decision.Kind]++
		}
		kinds := slices.SortedFunc(maps.Keys(counts), func(left, right decisionlog.Kind) int {
			if order := cmp.Compare(counts[right], counts[left]); order != 0 {
				return order
			}
			return cmp.Compare(left, right)
		})
		var phrases []string
		for index, kind := range kinds {
			if index == 4 {
				rest := 0
				for _, other := range kinds[4:] {
					rest += counts[other]
				}
				phrases = append(phrases, fmt.Sprintf("%d other", rest))
				break
			}
			phrases = append(phrases, KindPhrase(kind, counts[kind]))
		}
		noun := "decisions"
		if len(decisions) == 1 {
			noun = "decision"
		}
		made := fmt.Sprintf("%d %s", len(decisions), noun)
		if input.DecisionsTruncated || input.DecisionsPartial {
			made = "at least " + made
		}
		sentences = append(sentences, fmt.Sprintf("In the last %s the orchestrator made %s in %s: %s.",
			window, made, scope, joinList(phrases)))
		if input.DecisionsPartial {
			sentences = append(sentences, "Part of the history could not be searched"+
				unansweredText(input.Unanswered)+", so these counts are lower bounds.")
		}
		sentences = append(sentences, notable(decisions)...)
	}
	for _, change := range input.Changes {
		if change.Time.Before(since) || change.Time.After(input.Now) {
			continue
		}
		switch change.Type {
		case ChangeOpened:
			summary.Opened++
		case ChangeResolved:
			summary.Resolved++
		}
	}
	if summary.Opened > 0 || summary.Resolved > 0 {
		atLeast := ""
		if input.ChangesTruncated {
			atLeast = "At least "
		}
		sentence := fmt.Sprintf("%s opened and %s resolved", countNoun(summary.Opened, "problem", "problems"),
			countNoun(summary.Resolved, "problem", "problems"))
		if atLeast != "" {
			sentence = atLeast + lowerFirst(sentence)
		}
		if input.AttentionScope != "" {
			sentence += " in " + input.AttentionScope
		}
		sentences = append(sentences, sentence+".")
	}
	open := slices.Clone(input.Open)
	Rank(open)
	where := ""
	if input.AttentionScope != "" {
		where = " in " + input.AttentionScope
	}
	switch {
	case len(open) == 0:
		sentences = append(sentences, "Nothing needs attention"+where+" right now.")
	default:
		var parts []string
		if summary.Open.Critical > 0 {
			parts = append(parts, countNoun(summary.Open.Critical, "critical problem", "critical problems"))
		}
		if summary.Open.Warning > 0 {
			parts = append(parts, countNoun(summary.Open.Warning, "warning", "warnings"))
		}
		if summary.Open.Info > 0 {
			parts = append(parts, countNoun(summary.Open.Info, "note", "notes"))
		}
		verb := "needs"
		if len(open) > 1 {
			verb = "need"
		}
		sentences = append(sentences, fmt.Sprintf("Now %s %s attention%s, most urgently: %s.", joinList(parts), verb,
			where, strings.TrimSuffix(open[0].Title, ".")))
	}
	summary.Sentences = sentences
	summary.Text = strings.Join(sentences, " ")
	return summary
}

func unansweredText(regions []string) string {
	if len(regions) == 0 {
		return ""
	}
	upper := make([]string, len(regions))
	for index, region := range regions {
		upper[index] = strings.ToUpper(region)
	}
	verb := "did"
	return " (" + joinList(upper) + " " + verb + " not answer)"
}

// notable calls out the decisions an operator most wants to hear about,
// newest first, at most three.
func notable(decisions []decisionlog.Decision) []string {
	var out []string
	add := func(sentence string) bool {
		out = append(out, sentence)
		return len(out) < 3
	}
	failed := 0
	for _, decision := range decisions {
		if decision.Status == decisionlog.StatusFailed {
			failed++
		}
	}
	for _, decision := range decisions {
		var sentence string
		switch decision.Kind {
		case decisionlog.KindRollback:
			sentence = "A rollback of " + subjectText(decision) + " was decided" + because(decision) + "."
		case decisionlog.KindQuorumDegraded:
			sentence = "Quorum degraded on " + memberText(decision) + because(decision) + "."
		case decisionlog.KindLeaderChanged:
			sentence = "Authority leadership moved to " + subjectText(decision) + epochText(decision) + "."
		case decisionlog.KindCanaryPromoted, decisionlog.KindRolloutCompleted:
			sentence = upperFirst(KindPhrase(decision.Kind, 1)[2:]) + ": " + subjectText(decision) + "."
		default:
			continue
		}
		if !add(sentence) {
			break
		}
	}
	if failed > 0 && len(out) < 4 {
		out = append(out, countNoun(failed, "decision", "decisions")+" failed.")
	}
	return out
}

func subjectText(decision decisionlog.Decision) string {
	if decision.Subject.Name != "" {
		return decision.Subject.Name
	}
	if decision.Subject.ID != "" {
		return shortID(decision.Subject.ID)
	}
	return "an unnamed subject"
}

func memberText(decision decisionlog.Decision) string {
	if decision.Actor.Member != "" {
		return decision.Actor.Member
	}
	return subjectText(decision)
}

func because(decision decisionlog.Decision) string {
	reason := strings.TrimSuffix(strings.TrimSpace(decision.Reason), ".")
	if reason == "" {
		return ""
	}
	return " because " + lowerFirst(reason)
}

func epochText(decision decisionlog.Decision) string {
	if decision.Epoch == 0 {
		return ""
	}
	return fmt.Sprintf(" (epoch %d)", decision.Epoch)
}

func countNoun(count int, singular, plural string) string {
	if count == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", count, plural)
}

func joinList(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	default:
		return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
	}
}

func upperFirst(text string) string {
	if text == "" {
		return text
	}
	return strings.ToUpper(text[:1]) + text[1:]
}

func lowerFirst(text string) string {
	if len(text) < 2 || strings.ToUpper(text[:2]) == text[:2] {
		return text // keep acronyms such as "OCI"
	}
	return strings.ToLower(text[:1]) + text[1:]
}

// Summarizer builds summaries from live providers. It is the provider the
// dashboard's summary panel calls.
type Summarizer struct {
	Decisions decisionlog.Source
	Insights  Source
	// Regions restricts decisions; empty means every region the decision
	// source answers for.
	Regions []string
	Scope   string
	// AttentionScope names what Insights covers when narrower than Scope
	// (the local engine in an all-regions summary).
	AttentionScope string
	Now            func() time.Time
}

// changeRetention is implemented by sources that drop old changes.
type changeRetention interface {
	// ChangesComplete reports whether every change at or after since is
	// still held.
	ChangesComplete(since time.Time) bool
}

// Summary generates the paragraph for the window ending now.
func (summarizer Summarizer) Summary(ctx context.Context, window time.Duration) (Summary, error) {
	now := time.Now()
	if summarizer.Now != nil {
		now = summarizer.Now()
	}
	now = now.UTC()
	input := SummaryInput{Now: now, Window: window, Scope: summarizer.Scope, AttentionScope: summarizer.AttentionScope}
	if summarizer.Decisions != nil {
		result, err := summarizer.Decisions.Query(ctx, decisionlog.Query{Regions: summarizer.Regions,
			Since: now.Add(-window), Until: now.Add(time.Nanosecond), Limit: decisionlog.MaxQueryLimit})
		if err != nil {
			return Summary{}, err
		}
		input.Decisions = result.Decisions
		input.DecisionsTruncated = result.Truncated
		input.DecisionsPartial = result.Partial
		for _, status := range result.Regions {
			if status.State != decisionlog.RegionOK {
				input.DecisionsPartial = true
				input.Unanswered = append(input.Unanswered, status.Region)
			}
		}
	}
	if summarizer.Insights != nil {
		input.Changes = summarizer.Insights.Changes(now.Add(-window))
		input.Open = summarizer.Insights.Current().Insights
		if retention, ok := summarizer.Insights.(changeRetention); ok {
			input.ChangesTruncated = !retention.ChangesComplete(now.Add(-window))
		}
	}
	return Summarize(input), nil
}
