// Package observability contains the bounded, fail-closed boundary used by
// the orchestrator's eventual Grafana Cloud composition root.
package observability

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Signal identifies a Grafana Cloud ingestion endpoint. Page events are not a
// Signal: they are sent through PageSink and can never enter a telemetry
// batch.
type Signal uint8

const (
	SignalMetrics Signal = iota + 1
	SignalLogs
)

func (s Signal) String() string {
	switch s {
	case SignalMetrics:
		return "metrics"
	case SignalLogs:
		return "logs"
	default:
		return "unknown"
	}
}

// Credentials contains the Grafana Cloud basic-auth pair. APIKey is never
// included in an error or request description.
type Credentials struct {
	Username string
	APIKey   string
}

// Config is explicit configuration for one regional observability boundary.
// Zero values are intentionally invalid: an unconfigured exporter must fail
// closed rather than silently dropping its security boundary.
type Config struct {
	MetricsEndpoint string
	LogsEndpoint    string
	Credentials     Credentials
	Labels          LabelAllowList
	Batch           BatchConfig
	Retry           RetryPolicy
}

// ValidateConfig validates all security and resource bounds before a
// transport or batcher can be constructed.
func ValidateConfig(config Config) error {
	if err := validateHTTPSURL("MetricsEndpoint", config.MetricsEndpoint); err != nil {
		return err
	}
	if err := validateHTTPSURL("LogsEndpoint", config.LogsEndpoint); err != nil {
		return err
	}
	if err := validateCredential("Credentials.Username", config.Credentials.Username); err != nil {
		return err
	}
	if err := validateCredential("Credentials.APIKey", config.Credentials.APIKey); err != nil {
		return err
	}
	if config.Labels == nil {
		return errors.New("observability label allow-list is required")
	}
	if err := config.Labels.Validate(); err != nil {
		return err
	}
	if err := config.Batch.Validate(); err != nil {
		return err
	}
	return config.Retry.Validate()
}

func validateHTTPSURL(name, raw string) error {
	if raw == "" || len(raw) > 2048 {
		return fmt.Errorf("%s must be a non-empty URL no longer than 2048 bytes", name)
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%s must be an HTTPS URL with no credentials, query, or fragment", name)
	}
	return nil
}

func validateCredential(name, value string) error {
	if value == "" || len(value) > 512 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("%s must be a bounded, non-whitespace credential", name)
	}
	return nil
}

// BatchConfig bounds both records and bytes held in memory by one batch.
type BatchConfig struct {
	MaxItems int
	MaxBytes int
}

func (c BatchConfig) Validate() error {
	if c.MaxItems < 1 || c.MaxItems > 10_000 {
		return errors.New("batch MaxItems must be between 1 and 10000")
	}
	if c.MaxBytes < 1 || c.MaxBytes > 16*1024*1024 {
		return errors.New("batch MaxBytes must be between 1 and 16 MiB")
	}
	return nil
}

// RetryPolicy describes bounded retry behavior. Sleep is injectable for
// deterministic tests; nil uses a cancellation-aware timer.
type RetryPolicy struct {
	MaxAttempts  int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
	Sleep        func(ctx context.Context, delay time.Duration) error
}

func (p RetryPolicy) Validate() error {
	if p.MaxAttempts < 1 || p.MaxAttempts > 10 {
		return errors.New("retry MaxAttempts must be between 1 and 10")
	}
	if p.InitialDelay <= 0 || p.MaxDelay < p.InitialDelay || p.MaxDelay > 5*time.Minute {
		return errors.New("retry delays must be positive, ordered, and no longer than 5 minutes")
	}
	if p.Multiplier < 1 || p.Multiplier > 4 {
		return errors.New("retry Multiplier must be between 1 and 4")
	}
	return nil
}

// Retry runs operation at most MaxAttempts times and never waits past ctx's
// cancellation. The operation receives the same context on each attempt.
func Retry(ctx context.Context, policy RetryPolicy, operation func(context.Context) error) error {
	if ctx == nil {
		return errors.New("retry context must not be nil")
	}
	if operation == nil {
		return errors.New("retry operation is required")
	}
	if err := policy.Validate(); err != nil {
		return err
	}

	delay := policy.InitialDelay
	var lastErr error
	for attempt := 0; attempt < policy.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		lastErr = operation(ctx)
		if lastErr == nil {
			return nil
		}
		if attempt == policy.MaxAttempts-1 {
			break
		}
		wait := policy.Sleep
		if wait == nil {
			wait = sleepWithContext
		}
		if err := wait(ctx, delay); err != nil {
			return err
		}
		next := time.Duration(float64(delay) * policy.Multiplier)
		if next < delay || next > policy.MaxDelay {
			next = policy.MaxDelay
		}
		delay = next
	}
	return lastErr
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
