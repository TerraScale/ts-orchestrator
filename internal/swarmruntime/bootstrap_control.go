package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/handoff"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rolloutmaintenance"
	containerd "github.com/containerd/containerd/v2/client"
)

type BootstrapRequest struct {
	ID          string `json:"id"`
	SourceTask  string `json:"sourceTask"`
	TargetImage string `json:"targetImage"`
	Owner       string `json:"owner"`
	Epoch       int64  `json:"epoch"`
}

func BootstrapSocket(state string) string {
	return filepath.Join(state, "terrabase-bootstrap", "control.sock")
}

// ArmBootstrap captures runtime identity itself; operator JSON cannot invent
// task pins, PIDs, service material or a private lifecycle capability.
func (e *Executor) ArmBootstrap(ctx context.Context, request BootstrapRequest) error {
	e.mu.Lock()
	source := e.bootstrapTasks[request.SourceTask]
	e.mu.Unlock()
	if source == nil || !source.regionalTerraBase() || source.task.NodeID != e.functionNodeID {
		return rolloutmaintenance.ErrFenced
	}
	task, err := source.runtimeTask(ctx)
	if err != nil {
		return err
	}
	status, err := task.Status(runtimeContext(ctx))
	if err != nil {
		return err
	}
	if status.Status != containerd.Running {
		return errors.New("bootstrap source must be running")
	}
	process, err := processIdentity(task.Pid())
	if err != nil {
		return err
	}
	member, err := os.Hostname()
	if err != nil || !NodeName.MatchString(member) {
		return errors.New("execution host has no admitted member identity")
	}

	pin := source.bootstrapPin()
	j := rolloutmaintenance.Job{ID: request.ID, Member: member, Source: pin, Target: rolloutmaintenance.Pin{Node: pin.Node, Service: pin.Service, Image: request.TargetImage}, Process: process, Owner: request.Owner, Epoch: request.Epoch}
	return e.bootstrap.Arm(ctx, j)
}

// ServeBootstrap exposes finite transactions only on a root-owned Unix socket.
// Workers have this socket too; it never opens Swarm's manager API on a worker.
func (e *Executor) ServeBootstrap(ctx context.Context, state string) error {
	if os.Geteuid() != 0 {
		return errors.New("bootstrap executor control requires root")
	}
	socket := BootstrapSocket(state)
	if err := os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	if err = os.Chmod(socket, 0600); err != nil {
		listener.Close()
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		j, err := e.bootstrap.Status(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		data, err := protocol.EncodeJSON(j)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /arm", func(w http.ResponseWriter, r *http.Request) {
		var input BootstrapRequest
		if err := readBootstrap(r, &input, 64<<10); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := e.ArmBootstrap(r.Context(), input); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /clear", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ID   string `json:"id"`
			Node string `json:"node,omitempty"`
		}
		if err := readBootstrap(r, &input, 4096); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		var err error
		if input.Node == "" {
			err = e.bootstrap.Clear(r.Context(), input.ID)
		} else {
			err = handoff.ClearPeer(r.Context(), input.Node, input.ID)
		}
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /prepull", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ID string `json:"id"`
		}
		if err := readBootstrap(r, &input, 4096); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		job, err := e.bootstrap.Status(r.Context())
		if err == nil && (job == nil || job.ID != input.ID) {
			err = rolloutmaintenance.ErrFenced
		}
		if err == nil {
			// Fetch only the held job's pinned target with its service's registry
			// labels, so the 60 s replace budget does not include the pull.
			err = e.prePullBootstrapTarget(r.Context(), *job)
		}
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /owner", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ID string `json:"id"`
		}
		if err := readBootstrap(r, &input, 4096); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		job, err := e.bootstrap.Status(r.Context())
		if err == nil && (job == nil || job.ID != input.ID) {
			err = rolloutmaintenance.ErrFenced
		}
		if err == nil {
			err = handoff.Bootstrap(r.Context(), "owner", *job)
		}
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /stage", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ID string `json:"id"`
		}
		if err := readBootstrap(r, &input, 4096); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		job, err := e.bootstrap.Status(r.Context())
		if err == nil && (job == nil || job.ID != input.ID) {
			err = rolloutmaintenance.ErrFenced
		}
		if err == nil {
			err = handoff.Bootstrap(r.Context(), "stage", *job)
		}
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /replace", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ID string `json:"id"`
		}
		if err := readBootstrap(r, &input, 4096); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := e.BootstrapDriver().Replace(r.Context(), input.ID); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()
	defer listener.Close()
	if err = server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("bootstrap executor control: %w", err)
	}
	return nil
}

func readBootstrap(r *http.Request, value any, limit int) error {
	data, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil {
		return err
	}
	return protocol.DecodeStrict(data, value, limit)
}

func (e *Executor) prePullBootstrapTarget(ctx context.Context, j rolloutmaintenance.Job) error {
	e.mu.Lock()
	var labels map[string]string
	for _, c := range e.bootstrapTasks {
		if c.task.ServiceID == j.Source.Service && c.regionalTerraBase() {
			labels = maps.Clone(c.task.ServiceAnnotations.Labels)
			break
		}
	}
	e.mu.Unlock()
	if labels == nil {
		return errors.New("no dispatched TerraBase task names the registry yet")
	}
	return e.PrePull(ctx, j.Target.Image, labels)
}
