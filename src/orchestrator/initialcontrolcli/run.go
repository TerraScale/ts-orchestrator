// Package initialcontrolcli runs the owner-admitted initial GRU process and
// reports bounded preliminary capture and publication status changes.
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
	return reportPreliminary(ctx, runtime, output)
}

type preliminaryRuntime interface {
	Completion() <-chan struct{}
	PreliminaryCapture() initialcontrol.PreliminaryCaptureStatus
	PreliminaryPublication() initialcontrol.PreliminaryPublicationStatus
}

func reportPreliminary(ctx context.Context, runtime preliminaryRuntime, output io.Writer) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	type event struct {
		PreliminaryCapture     initialcontrol.PreliminaryCaptureStatus     `json:"preliminaryCapture"`
		PreliminaryPublication initialcontrol.PreliminaryPublicationStatus `json:"preliminaryPublication"`
	}
	var previous event
	havePrevious := false
	emit := func() error {
		status := event{runtime.PreliminaryCapture(), runtime.PreliminaryPublication()}
		// Error fields are bounded public summaries even if a future worker
		// accidentally returns an underlying provider or filesystem error.
		if status.PreliminaryCapture.Error != "" {
			status.PreliminaryCapture.Error = "preliminary capture refused or incomplete"
		}
		if status.PreliminaryPublication.Error != "" {
			status.PreliminaryPublication.Error = "preliminary publication refused or incomplete"
		}
		if havePrevious && status == previous {
			return nil
		}
		if err := json.NewEncoder(output).Encode(status); err != nil {
			return errors.New("initial control: could not write preliminary status")
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
