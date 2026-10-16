// Package command defines the OCI operation boundary and shared response helpers.
package command

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"time"
)

// Client permits native tests to exercise provider operations without cloud access.
type Client interface {
	Call(context.Context, ...string) (map[string]any, error)
	Head(context.Context, ...string) error
}

func Object(v any) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected OCI object, got %T", v)
	}
	return m, nil
}

func Rows(v any) ([]map[string]any, error) {
	if v == nil {
		return nil, nil
	}
	a, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("expected OCI list, got %T", v)
	}
	rows := make([]map[string]any, 0, len(a))
	for _, v := range a {
		m, err := Object(v)
		if err != nil {
			return nil, err
		}
		rows = append(rows, m)
	}
	return rows, nil
}

func ID(row map[string]any) (string, error) {
	id, ok := row["id"].(string)
	if !ok || id == "" {
		return "", fmt.Errorf("OCI resource has no id")
	}
	return id, nil
}

func JSON(v any) string {
	b, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		panic(err)
	}
	return string(b)
}

// Pause honors cancellation during provider lifecycle polling.
func Pause(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
