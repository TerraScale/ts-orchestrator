package benchmark

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"io"
	"os/exec"
	"time"
)

const cleanupWait = 120 * time.Second

type workerControl struct {
	Type            string    `json:"type"`
	JobID           string    `json:"job_id"`
	Clean           bool      `json:"clean,omitempty"`
	Success         bool      `json:"success,omitempty"`
	Client          string    `json:"client,omitempty"`
	MeasurementFrom time.Time `json:"measurement_from,omitzero"`
}

func (g SSHGenerator) runWorker(ctx context.Context, job Job, emit func(Sample) error) error {
	ctx, cancel := context.WithTimeout(ctx, MaxRun)
	defer cancel()
	command := exec.CommandContext(ctx, "ssh", "-F", "/dev/null", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oClearAllForwardings=yes", "-oConnectTimeout=10", "--", g.User+"@"+g.Address, "timeout --signal=INT --kill-after=120s 900s nice -n 19 "+g.WorkerPath+" bench worker")
	stdin, err := command.StdinPipe()
	if err != nil {
		return err
	}
	defer stdin.Close()
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	command.Stderr = io.Discard
	// Keep SSH alive to receive cleanup acknowledgement after cancellation.
	command.Cancel = func() error {
		_ = json.NewEncoder(stdin).Encode(workerControl{Type: "cancel", JobID: job.ID})
		return stdin.Close()
	}
	command.WaitDelay = cleanupWait
	if err := command.Start(); err != nil {
		return errors.New("cannot start benchmark SSH worker")
	}
	streamErr := json.NewEncoder(stdin).Encode(job)
	fail := func(err error) {
		if streamErr == nil {
			streamErr = err
		}
		cancel()
	}
	if streamErr != nil {
		cancel()
	}
	reader := bufio.NewReaderSize(stdout, 256<<10)
	var acknowledgement *workerControl
	started := map[string]bool{}
	droppingLine := false
	for {
		line, readErr := reader.ReadSlice('\n')
		if readErr == bufio.ErrBufferFull {
			fail(fmt.Errorf("worker JSONL exceeded limits: %w", readErr))
			droppingLine = true
			continue
		}
		if droppingLine {
			droppingLine = false
		} else if len(line) > 0 {
			var control workerControl
			if json.Unmarshal(line, &control) != nil {
				fail(errors.New("worker returned invalid JSONL"))
			} else if control.Type == "worker_done" {
				if control.JobID != job.ID || acknowledgement != nil {
					fail(errors.New("invalid worker cleanup acknowledgement"))
				} else {
					acknowledgement = &control
				}
			} else if control.Type == "measurement_start" {
				if acknowledgement != nil || control.JobID != job.ID || !contains(job.Clients, control.Client) || started[control.Client] || control.MeasurementFrom.IsZero() {
					fail(errors.New("invalid worker measurement marker"))
				} else if ctx.Err() == nil && streamErr == nil {
					started[control.Client] = true
					if err := emit(Sample{Type: "measurement_start", Client: control.Client, Region: job.Region, TS: control.MeasurementFrom}); err != nil {
						fail(err)
					}
				}
			} else if acknowledgement != nil {
				fail(errors.New("worker emitted results after cleanup"))
			} else if ctx.Err() == nil && streamErr == nil {
				var sample Sample
				if err := json.Unmarshal(line, &sample); err != nil {
					streamErr = errors.New("worker returned invalid JSONL")
				} else if !started[sample.Client] {
					streamErr = errors.New("client result arrived before its measurement marker")
				} else {
					streamErr = emit(sample)
				}
				if streamErr != nil {
					cancel()
				}
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				fail(fmt.Errorf("worker stream disconnected: %w", readErr))
			}
			break
		}
	}
	if acknowledgement == nil {
		cancel()
	}
	waitErr := command.Wait()
	if acknowledgement == nil || !acknowledgement.Clean {
		return errors.Join(streamErr, ctx.Err(), errors.New("remote benchmark cleanup was not acknowledged"))
	}
	if streamErr != nil {
		return streamErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if waitErr != nil || !acknowledgement.Success {
		return errors.New("benchmark worker failed; inspect worker locally without printing credentials")
	}
	return nil
}

func workerSession(ctx context.Context, in io.Reader, out io.Writer, run func(context.Context, Job, io.Writer) error) (resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, MaxRun)
	defer cancel()
	decoder := json.NewDecoder(io.LimitReader(in, 1<<20))
	decoder.DisallowUnknownFields()
	var job Job
	if err := decoder.Decode(&job); err != nil || !entityid.Valid(job.ID) {
		return errors.New("invalid benchmark job")
	}
	if closer, ok := in.(io.Closer); ok {
		defer closer.Close()
	}
	// EOF also cancels the job when SSH disconnects before sending control.
	go func() {
		var control workerControl
		_ = decoder.Decode(&control)
		cancel()
	}()
	resultErr = run(ctx, job, out)
	var cleanupError *containerCleanupError
	ack := workerControl{Type: "worker_done", JobID: job.ID, Clean: !errors.As(resultErr, &cleanupError), Success: resultErr == nil}
	return errors.Join(resultErr, json.NewEncoder(out).Encode(ack))
}
