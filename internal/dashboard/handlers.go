package dashboard

import (
	"bytes"
	"context"
	"hash/fnv"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/a-h/templ"
	"github.com/starfederation/datastar-go/datastar"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

// eventBatch bounds how many queued events one stream patch carries.
const eventBatch = 64

func (dashboard *Dashboard) pageHandler(page page) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		current := dashboard.load(request.Context(), page, request.URL.Query())
		render(writer, request, layout(current))
	})
}

func (dashboard *Dashboard) login(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	render(writer, request, login(query.Get("failed") == "1", observability.LocalRedirectPath(query.Get("next"))))
}

func render(writer http.ResponseWriter, request *http.Request, component templ.Component) {
	var body bytes.Buffer
	if err := component.Render(request.Context(), &body); err != nil {
		slog.Warn("dashboard render failed", observability.ComponentKey, "dashboard", "error", err)
		http.Error(writer, "render failed", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = writer.Write(body.Bytes())
}

// acquireStream reserves one of the listener's live stream slots.
func (dashboard *Dashboard) acquireStream() bool {
	select {
	case dashboard.streams <- struct{}{}:
		return true
	default:
		return false
	}
}

func (dashboard *Dashboard) releaseStream() { <-dashboard.streams }

// streamHandler serves a page's Datastar stream. It re-renders the page
// content every interval and patches it only when the HTML changed, so an
// idle cell costs one render per tick and no bytes on the wire. The events
// page instead follows the event bus and prepends new rows as they arrive.
func (dashboard *Dashboard) streamHandler(page page) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !dashboard.acquireStream() {
			writer.Header().Set("Retry-After", "10")
			http.Error(writer, "too many live dashboard streams", http.StatusServiceUnavailable)
			return
		}
		defer dashboard.releaseStream()
		query := request.URL.Query()
		sse := datastar.NewSSE(writer, request)
		if page.slug == "events" && dashboard.options.Events != nil {
			dashboard.streamEvents(request.Context(), sse, page, query)
			return
		}
		dashboard.streamContent(request.Context(), sse, page, query)
	})
}

// streamContent re-renders the page content and the live parts of the page
// chrome (region switcher, attention badge) every tick, and raises a toast
// as soon as the insight engine opens or escalates an insight.
func (dashboard *Dashboard) streamContent(ctx context.Context, sse *datastar.ServerSentEventGenerator, page page,
	query url.Values,
) {
	ticker := time.NewTicker(dashboard.options.Interval)
	defer ticker.Stop()
	var last uint64
	var changes <-chan insights.Change
	for {
		if changes == nil {
			if journal := dashboard.journal.Load(); journal != nil && journal.Insights != nil {
				changes = journal.Insights.Subscribe(ctx, 16)
			}
		}
		current := dashboard.load(ctx, page, query)
		var body bytes.Buffer
		if err := page.body(current).Render(ctx, &body); err != nil {
			return
		}
		if err := chrome(current).Render(ctx, &body); err != nil {
			return
		}
		digest := fnv.New64a()
		_, _ = digest.Write(body.Bytes())
		if sum := digest.Sum64(); sum != last {
			last = sum
			if err := sse.PatchElements(body.String()); err != nil {
				return
			}
		}
		for waiting := true; waiting; {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				waiting = false
			case change, open := <-changes:
				if !open {
					changes, waiting = nil, false
					continue
				}
				if err := toast(ctx, sse, current.State, change); err != nil {
					return
				}
			}
		}
	}
}

// toast raises a toast for an opened or escalated insight.
func toast(ctx context.Context, sse *datastar.ServerSentEventGenerator, state uiState, change insights.Change) error {
	if change.Type == insights.ChangeResolved {
		return nil
	}
	var toastHTML bytes.Buffer
	if err := insightToast(state, change).Render(ctx, &toastHTML); err != nil {
		return err
	}
	return sse.PatchElements(toastHTML.String(), datastar.WithSelectorID("toasts"), datastar.WithModeAppend())
}

// chromeRefresher re-renders the live top-bar parts (region switcher,
// attention badge) and patches them when they changed.
type chromeRefresher struct {
	dashboard *Dashboard
	page      page
	query     url.Values
	last      uint64
}

func (refresher *chromeRefresher) refresh(ctx context.Context, sse *datastar.ServerSentEventGenerator) (uiState, error) {
	current := refresher.dashboard.load(ctx, refresher.page, refresher.query)
	var body bytes.Buffer
	if err := chrome(current).Render(ctx, &body); err != nil {
		return current.State, err
	}
	digest := fnv.New64a()
	_, _ = digest.Write(body.Bytes())
	if sum := digest.Sum64(); sum != refresher.last {
		refresher.last = sum
		return current.State, sse.PatchElements(body.String())
	}
	return current.State, nil
}

// streamEvents first replaces the listed rows, so a reconnecting browser has
// no gap and no duplicate, then prepends each new matching event. Every
// maxRows prepended rows it replaces the list again to bound the page. Like
// every other page stream it also keeps the top bar current and raises
// insight toasts, all written from this one loop.
func (dashboard *Dashboard) streamEvents(ctx context.Context, sse *datastar.ServerSentEventGenerator, page page,
	query url.Values,
) {
	filter := parseEventFilter(query)
	source := dashboard.options.Events
	ticker := time.NewTicker(dashboard.options.Interval)
	defer ticker.Stop()
	chromeState := &chromeRefresher{dashboard: dashboard, page: page, query: query}
	state := parseState(query)
	var err error
	var changes <-chan insights.Change
	subscribe := func() {
		if changes == nil {
			if journal := dashboard.journal.Load(); journal != nil && journal.Insights != nil {
				changes = journal.Insights.Subscribe(ctx, 16)
			}
		}
	}
	subscribe()
	// Subscribe before listing so nothing published in between is lost;
	// the sequence check drops what the listing already contains.
	live := source.Subscribe(ctx, 256)
	var seen uint64
	empty := false
	reset := func() bool {
		events := filter.apply(source.Recent(0), page.events)
		if len(events) > 0 {
			seen = max(seen, events[0].Sequence)
		}
		empty = len(events) == 0
		return sse.PatchElementTempl(eventRows(events, "events-rows")) == nil
	}
	if !reset() {
		return
	}
	if state, err = chromeState.refresh(ctx, sse); err != nil {
		return
	}
	prepended := 0
	for {
		var batch []observability.Event
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			subscribe()
			if state, err = chromeState.refresh(ctx, sse); err != nil {
				return
			}
			continue
		case change, open := <-changes:
			if !open {
				changes = nil
				continue
			}
			if err := toast(ctx, sse, state, change); err != nil {
				return
			}
			continue
		case event, open := <-live:
			if !open {
				return
			}
			batch = append(batch, event)
		}
	drain:
		for len(batch) < eventBatch {
			select {
			case event, open := <-live:
				if !open {
					break drain
				}
				batch = append(batch, event)
			default:
				break drain
			}
		}
		// Rows are newest first: prepend the batch newest first as one patch.
		var fresh []observability.Event
		for index := len(batch) - 1; index >= 0; index-- {
			if batch[index].Sequence > seen && filter.matches(batch[index]) {
				fresh = append(fresh, batch[index])
			}
		}
		if len(fresh) == 0 {
			continue
		}
		seen = max(seen, fresh[0].Sequence)
		prepended += len(fresh)
		if prepended > page.events {
			if !reset() {
				return
			}
			prepended = 0
			continue
		}
		var rows bytes.Buffer
		for _, event := range fresh {
			if err := eventRow(event).Render(ctx, &rows); err != nil {
				return
			}
		}
		if err := sse.PatchElements(rows.String(), datastar.WithSelectorID("events-rows"),
			datastar.WithModePrepend()); err != nil {
			return
		}
		if empty {
			empty = false
			if err := sse.RemoveElementByID("events-rows-empty"); err != nil {
				return
			}
		}
	}
}
