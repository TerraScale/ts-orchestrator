package observability

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// DashboardObservation is a cause or health fact. Its type has no paging
// method, so a cause observation cannot accidentally be routed to OnCall.
type DashboardObservation struct {
	Name      string
	Labels    map[string]string
	Value     float64
	Timestamp time.Time
}

// SLOBurnRatePageEvent is the only event accepted by PageSink. It models a
// customer-visible SLO burn and deliberately has no generic cause/severity
// field that could turn an infrastructure fact into a page.
type SLOBurnRatePageEvent struct {
	Name      string
	Labels    map[string]string
	BurnRate  float64
	Window    string
	Timestamp time.Time
}

// DashboardSink receives dashboard-only observations.
type DashboardSink interface {
	Observe(ctx context.Context, observation DashboardObservation) error
}

// PageSink receives only SLO burn-rate events. It is intentionally separate
// from DashboardSink and the telemetry BatchSender.
type PageSink interface {
	Page(ctx context.Context, event SLOBurnRatePageEvent) error
}

// EventRouter routes the two event classes through distinct interfaces.
type EventRouter struct {
	dashboard DashboardSink
	page      PageSink
	labels    LabelAllowList
}

func NewEventRouter(labels LabelAllowList, dashboard DashboardSink, page PageSink) (*EventRouter, error) {
	if err := labels.Validate(); err != nil {
		return nil, err
	}
	if dashboard == nil || page == nil {
		return nil, errors.New("dashboard and page sinks are required")
	}
	return &EventRouter{dashboard: dashboard, page: page, labels: labels.Clone()}, nil
}

// EmitObservation can only reach the dashboard sink.
func (r *EventRouter) EmitObservation(ctx context.Context, observation DashboardObservation) error {
	if r == nil || r.dashboard == nil {
		return errors.New("dashboard sink is unavailable")
	}
	if err := validateEventContext(ctx); err != nil {
		return err
	}
	if err := validateEventName(observation.Name); err != nil {
		return err
	}
	if math.IsNaN(observation.Value) || math.IsInf(observation.Value, 0) {
		return errors.New("dashboard observation value must be finite")
	}
	if err := r.labels.ValidateLabels(observation.Labels); err != nil {
		return err
	}
	observation.Labels = cloneLabels(observation.Labels)
	return r.dashboard.Observe(ctx, observation)
}

// EmitPage can only reach the page sink and accepts only the canonical SLO
// burn-rate event name prefix and fixed windows.
func (r *EventRouter) EmitPage(ctx context.Context, event SLOBurnRatePageEvent) error {
	if r == nil || r.page == nil {
		return errors.New("page sink is unavailable")
	}
	if err := validateEventContext(ctx); err != nil {
		return err
	}
	if !strings.HasPrefix(event.Name, "slo.burn_rate.") {
		return errors.New("only SLO burn-rate events may page")
	}
	if err := validateEventName(event.Name); err != nil {
		return err
	}
	if event.BurnRate <= 0 || event.BurnRate > 1_000_000 || math.IsNaN(event.BurnRate) || math.IsInf(event.BurnRate, 0) {
		return errors.New("SLO burn rate must be positive and bounded")
	}
	if event.Window != "5m" && event.Window != "30m" && event.Window != "1h" && event.Window != "6h" {
		return fmt.Errorf("unsupported SLO burn window %q", event.Window)
	}
	if err := r.labels.ValidateLabels(event.Labels); err != nil {
		return err
	}
	event.Labels = cloneLabels(event.Labels)
	return r.page.Page(ctx, event)
}

func validateEventContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("event context must not be nil")
	}
	return ctx.Err()
}

func validateEventName(name string) error {
	if name == "" || len(name) > 128 || strings.ContainsAny(name, "\r\n") {
		return errors.New("event name must be non-empty, bounded, and control-free")
	}
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
		return fmt.Errorf("event name %q has an empty or malformed segment", name)
	}
	for index := range name {
		character := name[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return fmt.Errorf("event name %q contains an invalid character", name)
	}
	return nil
}

func cloneLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return nil
	}
	copyOf := make(map[string]string, len(labels))
	for key, value := range labels {
		copyOf[key] = value
	}
	return copyOf
}
