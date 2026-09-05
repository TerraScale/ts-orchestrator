// Package initialcontrolcli runs the owner-admitted initial GRU process and
// reports bounded local preliminary-capture status changes.
package initialcontrolcli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/initialcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
)

func Run(ctx context.Context, path string, output io.Writer) (result error) {
	if ctx == nil || output == nil {
		return errors.New("initial control requires context and status output")
	}
	raw, err := initialgrant.ReadConfiguration(path)
	if err != nil {
		return err
	}
	admission, err := initialgrant.AdmitConfiguration(ctx, raw)
	if err != nil {
		return err
	}
	runtime, err := initialcontrol.Start(ctx, admission)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, runtime.Close(), runtime.Err()) }()
	return reportCapture(ctx, runtime, output)
}

type captureRuntime interface {
	Completion() <-chan struct{}
	PreliminaryCapture() initialcontrol.PreliminaryCaptureStatus
}

func reportCapture(ctx context.Context, runtime captureRuntime, output io.Writer) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var previous initialcontrol.PreliminaryCaptureStatus
	havePrevious := false
	emit := func() error {
		status := runtime.PreliminaryCapture()
		if havePrevious && status == previous {
			return nil
		}
		if err := json.NewEncoder(output).Encode(struct {
			PreliminaryCapture initialcontrol.PreliminaryCaptureStatus `json:"preliminaryCapture"`
		}{status}); err != nil {
			return errors.New("initial control: could not write preliminary capture status")
		}
		previous, havePrevious = status, true
		return nil
	}
	for {
		if err := emit(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-runtime.Completion():
			return emit()
		case <-ticker.C:
		}
	}
}
