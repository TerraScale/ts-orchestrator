package dashboard

import (
	"bytes"
	"context"
	"hash/fnv"
	"log/slog"
	"net/http"
	"time"

	"github.com/a-h/templ"
	"github.com/starfederation/datastar-go/datastar"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

// eventBatch bounds how many queued events one stream patch carries.
const eventBatch = 64

func (dashboard *Dashboard) pageHandler(page page) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		current := dashboard.load(request.Context(), page, parseEventFilter(request.URL.Query()))
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
		filter := parseEventFilter(request.URL.Query())
		sse := datastar.NewSSE(writer, request)
		if page.slug == "events" && dashboard.options.Events != nil {
			dashboard.streamEvents(request.Context(), sse, page, filter)
			return
		}
		dashboard.streamContent(request.Context(), sse, page, filter)
	})
}

func (dashboard *Dashboard) streamContent(ctx context.Context, sse *datastar.ServerSentEventGenerator, page page,
	filter eventFilter,
) {
	ticker := time.NewTicker(dashboard.options.Interval)
	defer ticker.Stop()
	var last uint64
	for {
		current := dashboard.load(ctx, page, filter)
		var body bytes.Buffer
		if err := page.body(current).Render(ctx, &body); err != nil {
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
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// streamEvents first replaces the listed rows, so a reconnecting browser has
// no gap and no duplicate, then prepends each new matching event. Every
// maxRows prepended rows it replaces the list again to bound the page.
func (dashboard *Dashboard) streamEvents(ctx context.Context, sse *datastar.ServerSentEventGenerator, page page,
	filter eventFilter,
) {
	source := dashboard.options.Events
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
	prepended := 0
	for {
		var batch []observability.Event
		select {
		case <-ctx.Done():
			return
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
