// Package command provides the cancellable OCI CLI boundary used by deployment tools.
package command

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"os/exec"
	"time"
)

// Client permits native tests to exercise provider operations without cloud access.
type Client interface {
	Call(context.Context, ...string) (map[string]any, error)
	Head(context.Context, ...string) error
}

type CLI struct{ Region string }

func (c CLI) execute(ctx context.Context, args []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if c.Region != "" {
		args = append([]string{"--region", c.Region}, args...)
	}
	cmd := exec.CommandContext(ctx, "oci", args...)
	cmd.WaitDelay = 2 * time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("oci %v failed: %s: %w", args, stderr.String(), err)
	}
	return output, nil
}

func (c CLI) Call(ctx context.Context, args ...string) (map[string]any, error) {
	output, err := c.execute(ctx, append(args, "--output", "json"))
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(output)) == 0 {
		return map[string]any{}, nil
	}
	var result map[string]any
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("decode OCI response: %w", err)
	}
	return result, nil
}

func (c CLI) Head(ctx context.Context, args ...string) error {
	_, err := c.execute(ctx, args)
	return err
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
