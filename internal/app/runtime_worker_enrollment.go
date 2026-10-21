package app

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

const runtimeWorkerTransportFilename = "host-runtime-worker.json"

type runtimeWorkerBinding struct {
	Query   swarmruntime.WorkerRegistrationQuery `json:"query"`
	Binding hostenroll.SwarmNodeBinding          `json:"binding"`
}

func (enrollment *managedHostEnrollment) prepareRuntimeWorker(ctx context.Context, epoch uint64, request, response []byte) ([]byte, error) {
	if err := enrollment.fencer.Guard(ctx, epoch); err != nil {
		return nil, err
	}
	if enrollment.runtimeIdentity.Validate() != nil {
		return nil, errors.New("accepted root runtime identity is unavailable for worker enrollment")
	}
	_, descriptor, err := hostenroll.ParseRetainedWorkerRequest(request, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if descriptor.IsController() {
		return enrollment.prepareRuntimeControllerHost(ctx, epoch, request, response)
	}
	wire, err := swarmruntime.PrepareEnrolledWorker(ctx, enrollment.runtimeIdentity, swarmruntime.WorkerRegistrationQuery{Request: request, Response: response})
	if err != nil {
		return nil, err
	}
	if err := enrollment.fencer.Guard(ctx, epoch); err != nil {
		return nil, err
	}
	return wire, nil
}

func (enrollment *managedHostEnrollment) refreshRuntimeWorker(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.TLS == nil || request.Header.Get("Forwarded") != "" ||
		request.Header.Get("X-Forwarded-For") != "" || request.Header.Get("X-Real-IP") != "" {
		http.Error(writer, "invalid worker refresh transport", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 30*time.Second)
	defer cancel()
	epoch := enrollment.fencer.Current().Epoch
	if err := enrollment.fencer.Guard(ctx, epoch); err != nil {
		http.Error(writer, "regional authority is not writable", http.StatusServiceUnavailable)
		return
	}
	wire, err := io.ReadAll(io.LimitReader(request.Body, (128<<10)+1))
	var transport hostenroll.WorkerTransport
	if err != nil || protocol.DecodeStrict(wire, &transport, 128<<10) != nil {
		http.Error(writer, "invalid worker refresh", http.StatusBadRequest)
		return
	}
	enrolled, descriptor, err := hostenroll.ParseRetainedWorkerRequest(transport.Request, time.Now().UTC())
	peer, _, peerErr := net.SplitHostPort(request.RemoteAddr)
	if err != nil || peerErr != nil || net.ParseIP(peer) == nil || enrollment.observeRuntimeWorkerPeer(ctx, peer, enrolled, descriptor) != nil {
		http.Error(writer, "worker peer is not current", http.StatusForbidden)
		return
	}
	grant, _, err := hostenroll.ReadCurrentGrant(ctx, enrollment.js, enrolled.InstanceID)
	if err != nil || grant.Disabled || grant.TerminalOperationID != "" || grant.IdentityResetOperationID != "" ||
		!grant.MatchesCompletedWorkerEnrollment(transport) {
		http.Error(writer, "worker refresh requires current completed enrollment", http.StatusForbidden)
		return
	}
	response, err := enrollment.prepareRuntimeWorker(ctx, epoch, transport.Request, transport.Response)
	if err != nil {
		http.Error(writer, "worker projection is unavailable", http.StatusServiceUnavailable)
		return
	}
	if enrollment.fencer.Guard(ctx, epoch) != nil || enrollment.observeRuntimeWorkerPeer(ctx, peer, enrolled, descriptor) != nil {
		http.Error(writer, "worker authority changed", http.StatusServiceUnavailable)
		return
	}
	result, err := protocol.EncodeJSON(hostenroll.WorkerTransport{Request: transport.Request, Response: response})
	if err != nil {
		http.Error(writer, "worker refresh encoding failed", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_, _ = writer.Write(result)
}

func (enrollment *managedHostEnrollment) bindRuntimeWorker(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.TLS == nil || request.Header.Get("Forwarded") != "" ||
		request.Header.Get("X-Forwarded-For") != "" || request.Header.Get("X-Real-IP") != "" {
		http.Error(writer, "invalid worker binding transport", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 20*time.Second)
	defer cancel()
	epoch := enrollment.fencer.Current().Epoch
	if err := enrollment.fencer.Guard(ctx, epoch); err != nil {
		http.Error(writer, "regional authority is not writable", http.StatusServiceUnavailable)
		return
	}
	wire, err := io.ReadAll(io.LimitReader(request.Body, (128<<10)+1))
	if err != nil || len(wire) > 128<<10 {
		http.Error(writer, "worker binding is oversized", http.StatusRequestEntityTooLarge)
		return
	}
	var binding runtimeWorkerBinding
	if err := protocol.DecodeStrict(wire, &binding, 128<<10); err != nil || binding.Query.Swarm != nil {
		http.Error(writer, "invalid worker binding", http.StatusBadRequest)
		return
	}
	enrollmentRequest, descriptor, err := hostenroll.ParseRetainedWorkerRequest(binding.Query.Request, time.Now().UTC())
	peer, _, peerErr := net.SplitHostPort(request.RemoteAddr)
	if err != nil || peerErr != nil || net.ParseIP(peer) == nil {
		http.Error(writer, "invalid worker peer identity", http.StatusForbidden)
		return
	}
	if err := enrollment.observeRuntimeWorkerPeer(ctx, peer, enrollmentRequest, descriptor); err != nil {
		http.Error(writer, "worker peer is not current", http.StatusForbidden)
		return
	}
	if err := swarmruntime.AdmitEnrolledWorker(ctx, enrollment.runtimeIdentity, binding.Query, binding.Binding); err != nil {
		http.Error(writer, "worker binding admission is pending", http.StatusServiceUnavailable)
		return
	}
	if err := enrollment.fencer.Guard(ctx, epoch); err != nil {
		http.Error(writer, "regional authority changed", http.StatusServiceUnavailable)
		return
	}
	if err := enrollment.observeRuntimeWorkerPeer(ctx, peer, enrollmentRequest, descriptor); err != nil {
		http.Error(writer, "worker peer changed", http.StatusForbidden)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (enrollment *managedHostEnrollment) observeRuntimeWorkerPeer(ctx context.Context, peer string, request hostenroll.Request, descriptor hostboot.Descriptor) error {
	if descriptor.Cell != enrollment.cell || descriptor.Region != string(enrollment.region) {
		return errors.New("worker descriptor is outside this regional fleet")
	}
	if descriptor.IsStatic() {
		_, _, err := enrollment.observeStatic(ctx, peer, request, descriptor)
		return err
	}
	_, err := enrollment.observePeer(ctx, peer, request.InstanceID, descriptor)
	return err
}
