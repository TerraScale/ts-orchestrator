// Port of src/TerraScale.Orchestrator/Messaging/NatsOperationJournalMutationService.cs.
package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// natsOperationJournalMaximumValueBytes mirrors the C# private bound.
const natsOperationJournalMaximumValueBytes = 16 * 1024

// NatsOperationJournalMutationService mirrors the C# class: the private typed
// mutation boundary; only this service holds journal KV write credentials.
type NatsOperationJournalMutationService struct {
	service  *natsSvcServer
	replies  *NatsOperationJournalMutationReplySigner
	lifetime context.CancelFunc
}

// NatsOperationJournalMutationServiceStartAsync mirrors the C# StartAsync.
func NatsOperationJournalMutationServiceStartAsync(
	ctx context.Context,
	writer *nats.Conn,
	store jetstream.KeyValue,
	proofConsumptions jetstream.KeyValue,
	topology *NatsTopology,
	authority *NatsOperationJournalMutationAuthorityVerifier,
	controllerIdentities map[string]struct{},
	replies *NatsOperationJournalMutationReplySigner,
	enableRuntimeLifecycleProtocol bool,
) (*NatsOperationJournalMutationService, error) {
	if ctx == nil {
		return nil, errors.New("(Parameter 'ctx')")
	}
	if writer == nil {
		return nil, errors.New("(Parameter 'writer')")
	}

	if store == nil || proofConsumptions == nil || topology == nil {
		return nil, errors.New("(Parameter 'store')")
	}

	if authority == nil {
		return nil, errors.New("(Parameter 'authority')")
	}

	if len(controllerIdentities) == 0 {
		return nil, errors.New(
			"At least one controller identity is required. (Parameter 'controllerIdentities')")
	}

	for identity := range controllerIdentities {
		if strings.TrimSpace(identity) == "" {
			return nil, errors.New(
				"At least one controller identity is required. (Parameter 'controllerIdentities')")
		}
	}

	if replies == nil {
		return nil, errors.New("(Parameter 'replies')")
	}

	lifetimeCtx, lifetime := context.WithCancel(ctx)
	service := newNatsSvcServer(writer, natsSvcConfig{
		Name:        "terrascale_orchestrator_journal_writer_" + topology.Cell,
		Version:     "1.0.0",
		Description: "Private typed CreateNode journal mutation service",
		QueueGroup:  topology.OperationJournalWriterQueueGroup(),
	})

	createSubject, err := topology.OperationJournalCreateSubject()
	if err != nil {
		lifetime()
		return nil, err
	}

	updateSubject, err := topology.OperationJournalUpdateSubject()
	if err != nil {
		lifetime()
		return nil, err
	}

	if err := service.AddEndpoint(natsSvcEndpointConfig{
		Name:     "create",
		Subject:  createSubject,
		Metadata: map[string]string{"private": "true"},
		Handler: func(ctx context.Context, message *nats.Msg) error {
			return natsOperationJournalCreate(ctx, message, store, proofConsumptions,
				topology.Cell, authority, controllerIdentities, replies)
		},
	}); err != nil {
		lifetime()
		replies.Dispose()
		return nil, err
	}

	if err := service.AddEndpoint(natsSvcEndpointConfig{
		Name:     "update",
		Subject:  updateSubject,
		Metadata: map[string]string{"private": "true"},
		Handler: func(ctx context.Context, message *nats.Msg) error {
			return natsOperationJournalUpdate(ctx, message, store, proofConsumptions,
				topology.Cell, authority, controllerIdentities, replies)
		},
	}); err != nil {
		lifetime()
		replies.Dispose()
		return nil, err
	}

	if enableRuntimeLifecycleProtocol {
		if store.Bucket() != topology.Operations().Bucket ||
			proofConsumptions.Bucket() != topology.OperationProofConsumptions().Bucket {
			lifetime()
			replies.Dispose()
			return nil, errors.New(
				"The runtime lifecycle journal requires the dedicated operation and proof stores.")
		}

		readSubject, err := RuntimeLifecycleNatsProtocol.Subject(topology.Cell, "read")
		if err != nil {
			lifetime()
			replies.Dispose()
			return nil, err
		}

		writeSubject, err := RuntimeLifecycleNatsProtocol.Subject(topology.Cell, "write")
		if err != nil {
			lifetime()
			replies.Dispose()
			return nil, err
		}

		readHandler := func(ctx context.Context, message *nats.Msg) error {
			return natsOperationJournalReadRuntimeLifecycle(ctx, message, writer, topology,
				authority, controllerIdentities, replies)
		}

		writeHandler := func(ctx context.Context, message *nats.Msg) error {
			return natsOperationJournalWriteRuntimeLifecycle(ctx, message, writer, topology,
				authority, controllerIdentities, replies)
		}

		if err := service.AddEndpoint(natsSvcEndpointConfig{
			Name:     "runtime-lifecycle-read",
			Subject:  readSubject,
			Metadata: map[string]string{"private": "true"},
			Handler:  readHandler,
		}); err != nil {
			lifetime()
			replies.Dispose()
			return nil, err
		}

		if err := service.AddEndpoint(natsSvcEndpointConfig{
			Name:     "runtime-lifecycle-write",
			Subject:  writeSubject,
			Metadata: map[string]string{"private": "true"},
			Handler:  writeHandler,
		}); err != nil {
			lifetime()
			replies.Dispose()
			return nil, err
		}
	}

	if err := service.Start(lifetimeCtx); err != nil {
		lifetime()
		replies.Dispose()
		return nil, err
	}

	return &NatsOperationJournalMutationService{service: service, replies: replies, lifetime: lifetime}, nil
}

// Dispose mirrors the C# DisposeAsync.
func (s *NatsOperationJournalMutationService) Dispose() {
	if s == nil {
		return
	}
	if s.lifetime != nil {
		s.lifetime()
	}
	if s.service != nil {
		s.service.Stop()
	}
	if s.replies != nil {
		s.replies.Dispose()
	}
}

func natsOperationJournalCreate(
	ctx context.Context,
	message *nats.Msg,
	store jetstream.KeyValue,
	proofConsumptions jetstream.KeyValue,
	cell string,
	authority *NatsOperationJournalMutationAuthorityVerifier,
	controllerIdentities map[string]struct{},
	replies *NatsOperationJournalMutationReplySigner,
) error {
	var request NatsOperationJournalCreateRequest
	if err := json.Unmarshal(message.Data, &request); err != nil {
		return nil
	}

	if !natsOperationJournalIsValid(request.Key, request.Value) ||
		!authority.Verify(&request.Authority, cell, controllerIdentities, "create", request.Key, 0, request.Value) {
		return natsOperationJournalReply(ctx, message, request.Authority, false, 0, replies)
	}

	consumed, err := NatsOperationJournalMutationProofConsumptionTryConsumeAsync(
		ctx, proofConsumptions, request.Authority)
	if err != nil || !consumed {
		return natsOperationJournalReply(ctx, message, request.Authority, false, 0, replies)
	}

	revision, err := store.Create(ctx, request.Key, []byte(request.Value))
	if err != nil {
		return natsOperationJournalReply(ctx, message, request.Authority, false, 0, replies)
	}

	return natsOperationJournalReply(ctx, message, request.Authority, true, revision, replies)
}

func natsOperationJournalUpdate(
	ctx context.Context,
	message *nats.Msg,
	store jetstream.KeyValue,
	proofConsumptions jetstream.KeyValue,
	cell string,
	authority *NatsOperationJournalMutationAuthorityVerifier,
	controllerIdentities map[string]struct{},
	replies *NatsOperationJournalMutationReplySigner,
) error {
	var request NatsOperationJournalUpdateRequest
	if err := json.Unmarshal(message.Data, &request); err != nil {
		return nil
	}

	if !natsOperationJournalIsValid(request.Key, request.Value) || request.Revision == 0 ||
		!authority.Verify(&request.Authority, cell, controllerIdentities, "update", request.Key, request.Revision, request.Value) {
		return natsOperationJournalReply(ctx, message, request.Authority, false, 0, replies)
	}

	consumed, err := NatsOperationJournalMutationProofConsumptionTryConsumeAsync(
		ctx, proofConsumptions, request.Authority)
	if err != nil || !consumed {
		return natsOperationJournalReply(ctx, message, request.Authority, false, 0, replies)
	}

	revision, err := store.Update(ctx, request.Key, []byte(request.Value), request.Revision)
	if err != nil {
		return natsOperationJournalReply(ctx, message, request.Authority, false, 0, replies)
	}

	return natsOperationJournalReply(ctx, message, request.Authority, true, revision, replies)
}

func natsOperationJournalIsValid(key, value string) bool {
	if len(key) != 74 || !strings.HasPrefix(key, "operation.") {
		return false
	}

	for index := len("operation."); index < len(key); index++ {
		character := key[index]
		isHex := character >= '0' && character <= '9' ||
			character >= 'a' && character <= 'f' ||
			character >= 'A' && character <= 'F'
		if !isHex {
			return false
		}
	}

	return len([]byte(value)) <= natsOperationJournalMaximumValueBytes
}

func natsOperationJournalReply(
	ctx context.Context,
	message *nats.Msg,
	authority NatsOperationJournalMutationAuthorityProof,
	succeeded bool,
	revision uint64,
	replies *NatsOperationJournalMutationReplySigner,
) error {
	digest := NatsOperationJournalMutationRequestDigestCreate(authority)
	return message.Respond(natsMarshalServicePayload(replies.Sign(succeeded, revision, digest)))
}

func natsOperationJournalReadRuntimeLifecycle(
	ctx context.Context,
	message *nats.Msg,
	writer *nats.Conn,
	topology *NatsTopology,
	authority *NatsOperationJournalMutationAuthorityVerifier,
	controllerIdentities map[string]struct{},
	replies *NatsOperationJournalMutationReplySigner,
) error {
	var request NatsRuntimeLifecycleJournalReadRequest
	if err := json.Unmarshal(message.Data, &request); err != nil {
		return nil
	}

	readBinding := RuntimeLifecycleNatsProtocol.ProofBinding(RuntimeLifecycleNatsProtocolReadAction,
		request.SchemaVersion, request.Cell, request.Key, 0, 0, request.RequestId, nil)
	if !RuntimeLifecycleNatsProtocol.IsRequest(request.SchemaVersion, request.Cell, request.Key, request.RequestId) ||
		request.Cell != topology.Cell ||
		!authority.Verify(&request.Authority, topology.Cell, controllerIdentities,
			RuntimeLifecycleNatsProtocolReadAction, request.Key, 0, readBinding) {
		return nil
	}

	stores, err := natsOperationJournalOpenRuntimeLifecycleStores(ctx, writer, topology)
	if err != nil {
		return natsOperationJournalReplyRuntime(ctx, message,
			int(RuntimeLifecycleJournalReadStatusUnavailable), 0, nil, request.Authority, replies)
	}

	result, err := NatsOperationJournalMutationProofConsumptionConsumeAsync(
		ctx, stores.ProofConsumptions, request.Authority)
	if err != nil {
		return natsOperationJournalReplyRuntime(ctx, message,
			int(RuntimeLifecycleJournalReadStatusUnavailable), 0, nil, request.Authority, replies)
	}

	switch result {
	case NatsOperationJournalMutationProofConsumptionResultAlreadyConsumed:
		return natsOperationJournalReplyRuntime(ctx, message,
			int(RuntimeLifecycleJournalReadStatusAmbiguous), 0, nil, request.Authority, replies)
	case NatsOperationJournalMutationProofConsumptionResultUnavailable:
		return natsOperationJournalReplyRuntime(ctx, message,
			int(RuntimeLifecycleJournalReadStatusUnavailable), 0, nil, request.Authority, replies)
	}

	entry, err := stores.Operations.Get(ctx, request.Key)
	if err != nil {
		return natsOperationJournalReadErrorReply(ctx, message, err, request.Authority, replies)
	}

	checkpoint, valid := RuntimeLifecycleNatsProtocol.TryDeserialize(string(entry.Value()))
	if !valid ||
		!RuntimeLifecycleNatsProtocol.IsCheckpoint(&checkpoint, topology.Cell, request.Key, entry.Revision()) {
		return natsOperationJournalReplyRuntime(ctx, message,
			int(RuntimeLifecycleJournalReadStatusAmbiguous), 0, nil, request.Authority, replies)
	}

	value := string(entry.Value())
	return natsOperationJournalReplyRuntime(ctx, message, int(RuntimeLifecycleJournalReadStatusFound),
		entry.Revision(), &value, request.Authority, replies)
}

func natsOperationJournalReadErrorReply(
	ctx context.Context,
	message *nats.Msg,
	err error,
	authority NatsOperationJournalMutationAuthorityProof,
	replies *NatsOperationJournalMutationReplySigner,
) error {
	status := int(RuntimeLifecycleJournalReadStatusUnavailable)
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		status = int(RuntimeLifecycleJournalReadStatusMissing)
	}

	return natsOperationJournalReplyRuntime(ctx, message, status, 0, nil, authority, replies)
}

func natsOperationJournalWriteRuntimeLifecycle(
	ctx context.Context,
	message *nats.Msg,
	writer *nats.Conn,
	topology *NatsTopology,
	authority *NatsOperationJournalMutationAuthorityVerifier,
	controllerIdentities map[string]struct{},
	replies *NatsOperationJournalMutationReplySigner,
) error {
	var request NatsRuntimeLifecycleJournalWriteRequest
	if err := json.Unmarshal(message.Data, &request); err != nil {
		return nil
	}

	action := RuntimeLifecycleNatsProtocolUpdateAction
	if request.ExpectedRevision == 0 {
		action = RuntimeLifecycleNatsProtocolCreateAction
	}

	checkpointValid := false
	var checkpoint RuntimeLifecycleCheckpoint
	if parsed, ok := RuntimeLifecycleNatsProtocol.TryDeserialize(request.Checkpoint); ok {
		checkpoint = parsed
		checkpointValid = RuntimeLifecycleNatsProtocol.IsCheckpoint(&checkpoint,
			topology.Cell, request.Key, request.ExpectedRevision+1)
	}

	binding := RuntimeLifecycleNatsProtocol.ProofBinding(action, request.SchemaVersion,
		request.Cell, request.Key, request.ExpectedRevision, request.WriterEpoch,
		request.RequestId, &request.Checkpoint)
	if !RuntimeLifecycleNatsProtocol.IsRequest(request.SchemaVersion, request.Cell, request.Key, request.RequestId) ||
		request.Cell != topology.Cell ||
		!checkpointValid ||
		request.ExpectedRevision == ^uint64(0) || request.WriterEpoch == 0 ||
		request.WriterEpoch != checkpoint.WriterEpoch.Value ||
		!authority.Verify(&request.Authority, topology.Cell, controllerIdentities, action,
			request.Key, request.ExpectedRevision, binding) {
		return nil
	}

	unavailable := func() error {
		return natsOperationJournalReplyRuntime(ctx, message,
			int(RuntimeLifecycleJournalWriteStatusUnavailable), 0, nil, request.Authority, replies)
	}

	stores, err := natsOperationJournalOpenRuntimeLifecycleStores(ctx, writer, topology)
	if err != nil {
		return unavailable()
	}

	result, err := NatsOperationJournalMutationProofConsumptionConsumeAsync(
		ctx, stores.ProofConsumptions, request.Authority)
	if err != nil {
		return unavailable()
	}

	switch result {
	case NatsOperationJournalMutationProofConsumptionResultAlreadyConsumed:
		return natsOperationJournalReplyRuntime(ctx, message,
			int(RuntimeLifecycleJournalWriteStatusAmbiguous), 0, nil, request.Authority, replies)
	case NatsOperationJournalMutationProofConsumptionResultUnavailable:
		return unavailable()
	}

	if request.ExpectedRevision == 0 {
		if !RuntimeLifecycleNatsProtocol.IsGenesis(checkpoint) {
			return natsOperationJournalReplyRuntime(ctx, message,
				int(RuntimeLifecycleJournalWriteStatusAmbiguous), 0, nil, request.Authority, replies)
		}

		revision, err := stores.Operations.Create(ctx, request.Key, []byte(request.Checkpoint))
		if err != nil {
			return natsOperationJournalWriteErrorReply(ctx, message, err, request.Authority, replies)
		}

		return natsOperationJournalReplyRuntime(ctx, message, int(RuntimeLifecycleJournalWriteStatusApplied),
			revision, &request.Checkpoint, request.Authority, replies)
	}

	current, err := stores.Operations.Get(ctx, request.Key)
	if err != nil {
		return natsOperationJournalWriteErrorReply(ctx, message, err, request.Authority, replies)
	}

	if current.Revision() != request.ExpectedRevision {
		return natsOperationJournalReplyRuntime(ctx, message,
			int(RuntimeLifecycleJournalWriteStatusConflict), 0, nil, request.Authority, replies)
	}

	prior, priorValid := RuntimeLifecycleNatsProtocol.TryDeserialize(string(current.Value()))
	if !priorValid ||
		!RuntimeLifecycleNatsProtocol.IsCheckpoint(&prior, topology.Cell, request.Key, current.Revision()) ||
		!RuntimeLifecycleNatsProtocol.IsChained(prior, checkpoint) {
		return natsOperationJournalReplyRuntime(ctx, message,
			int(RuntimeLifecycleJournalWriteStatusAmbiguous), 0, nil, request.Authority, replies)
	}

	revision, err := stores.Operations.Update(ctx, request.Key, []byte(request.Checkpoint), request.ExpectedRevision)
	if err != nil {
		return natsOperationJournalWriteErrorReply(ctx, message, err, request.Authority, replies)
	}

	return natsOperationJournalReplyRuntime(ctx, message, int(RuntimeLifecycleJournalWriteStatusApplied),
		revision, &request.Checkpoint, request.Authority, replies)
}

func natsOperationJournalWriteErrorReply(
	ctx context.Context,
	message *nats.Msg,
	err error,
	authority NatsOperationJournalMutationAuthorityProof,
	replies *NatsOperationJournalMutationReplySigner,
) error {
	status := int(RuntimeLifecycleJournalWriteStatusUnavailable)
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		status = int(RuntimeLifecycleJournalWriteStatusMissing)
	}

	if errors.Is(err, jetstream.ErrKeyExists) || errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
		status = int(RuntimeLifecycleJournalWriteStatusConflict)
	}

	return natsOperationJournalReplyRuntime(ctx, message, status, 0, nil, authority, replies)
}

func natsOperationJournalReplyRuntime(
	ctx context.Context,
	message *nats.Msg,
	status int,
	revision uint64,
	checkpoint *string,
	authority NatsOperationJournalMutationAuthorityProof,
	replies *NatsOperationJournalMutationReplySigner,
) error {
	reply := replies.SignRuntime(status, revision, checkpoint,
		NatsOperationJournalMutationRequestDigestCreate(authority))
	return message.Respond(natsMarshalServicePayload(reply))
}

type natsRuntimeLifecycleJournalStores struct {
	Operations        jetstream.KeyValue
	ProofConsumptions jetstream.KeyValue
}

func natsOperationJournalOpenRuntimeLifecycleStores(
	ctx context.Context,
	writer *nats.Conn,
	topology *NatsTopology,
) (*natsRuntimeLifecycleJournalStores, error) {
	js, err := jetstream.New(writer)
	if err != nil {
		return nil, err
	}

	operations, err := NatsOperationJournalStore.OpenAsync(ctx, js, topology.Operations(), writer)
	if err != nil {
		return nil, err
	}

	proofConsumptions, err := NatsOperationJournalStore.OpenAsync(
		ctx, js, topology.OperationProofConsumptions(), writer)
	if err != nil {
		return nil, err
	}

	return &natsRuntimeLifecycleJournalStores{Operations: operations, ProofConsumptions: proofConsumptions}, nil
}

func natsMarshalServicePayload(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		return []byte("{}")
	}

	return encoded
}

// NatsOperationJournalMutationProofConsumptionResult mirrors the C# enum.
type NatsOperationJournalMutationProofConsumptionResult int

const (
	NatsOperationJournalMutationProofConsumptionResultConsumed        NatsOperationJournalMutationProofConsumptionResult = 1
	NatsOperationJournalMutationProofConsumptionResultAlreadyConsumed NatsOperationJournalMutationProofConsumptionResult = 2
	NatsOperationJournalMutationProofConsumptionResultUnavailable     NatsOperationJournalMutationProofConsumptionResult = 3
)

// NatsOperationJournalMutationProofConsumption mirrors the C# static class:
// the R3 create-only proof ledger. Entries expire within the maximum accepted
// proof lifetime.
var NatsOperationJournalMutationProofConsumption natsOperationJournalMutationProofConsumption

type natsOperationJournalMutationProofConsumption struct{}

// NatsOperationJournalMutationProofConsumptionTryConsumeAsync mirrors the C#
// TryConsumeAsync.
func NatsOperationJournalMutationProofConsumptionTryConsumeAsync(
	ctx context.Context,
	store jetstream.KeyValue,
	proof NatsOperationJournalMutationAuthorityProof,
) (bool, error) {
	result, err := NatsOperationJournalMutationProofConsumptionConsumeAsync(ctx, store, proof)
	if err != nil {
		return false, err
	}

	return result == NatsOperationJournalMutationProofConsumptionResultConsumed, nil
}

// NatsOperationJournalMutationProofConsumptionConsumeAsync mirrors the C#
// ConsumeAsync.
func NatsOperationJournalMutationProofConsumptionConsumeAsync(
	ctx context.Context,
	store jetstream.KeyValue,
	proof NatsOperationJournalMutationAuthorityProof,
) (NatsOperationJournalMutationProofConsumptionResult, error) {
	key, err := NatsOperationJournalMutationProofConsumptionKey(proof)
	if err != nil {
		return NatsOperationJournalMutationProofConsumptionResultUnavailable, err
	}

	_, err = store.Create(ctx, key, []byte("consumed"))
	if err == nil {
		return NatsOperationJournalMutationProofConsumptionResultConsumed, nil
	}

	if errors.Is(err, jetstream.ErrKeyExists) || errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
		return NatsOperationJournalMutationProofConsumptionResultAlreadyConsumed, nil
	}

	// A failed proof-ledger write must fail closed before the operation KV is
	// touched; providers never receive a mutation reply that authorizes reuse.
	return NatsOperationJournalMutationProofConsumptionResultUnavailable, nil
}

// NatsOperationJournalMutationProofConsumptionKey mirrors the C# Key.
func NatsOperationJournalMutationProofConsumptionKey(
	proof NatsOperationJournalMutationAuthorityProof,
) (string, error) {
	hash := sha256.New()
	for _, value := range []string{proof.Cell, proof.CallerIdentity, proof.Lease, proof.Nonce} {
		bytes := []byte(value)
		length := make([]byte, 4)
		length[0] = byte(len(bytes) >> 24)
		length[1] = byte(len(bytes) >> 16)
		length[2] = byte(len(bytes) >> 8)
		length[3] = byte(len(bytes))
		hash.Write(length)
		hash.Write(bytes)
	}

	return "proof." + hex.EncodeToString(hash.Sum(nil)), nil
}

// NatsOperationJournalMutationClient mirrors the C# class.
type NatsOperationJournalMutationClient struct {
	client    *nats.Conn
	topology  *NatsTopology
	authority *NatsOperationJournalMutationAuthoritySigner
	replies   *NatsOperationJournalMutationReplyVerifier
}

// NewNatsOperationJournalMutationClient mirrors the C# primary constructor.
func NewNatsOperationJournalMutationClient(
	client *nats.Conn,
	topology *NatsTopology,
	authority *NatsOperationJournalMutationAuthoritySigner,
	replies *NatsOperationJournalMutationReplyVerifier,
) *NatsOperationJournalMutationClient {
	return &NatsOperationJournalMutationClient{
		client:    client,
		topology:  topology,
		authority: authority,
		replies:   replies,
	}
}

// CreateAsync mirrors the C# CreateAsync.
func (c *NatsOperationJournalMutationClient) CreateAsync(
	ctx context.Context,
	key string,
	value string,
) (NatsOperationJournalMutationReply, error) {
	if err := c.validate(); err != nil {
		return NatsOperationJournalMutationReply{}, err
	}
	subject, err := c.topology.OperationJournalCreateSubject()
	if err != nil {
		return NatsOperationJournalMutationReply{}, err
	}

	proof := c.authority.Issue(c.topology.Cell, "create", key, 0, value)
	request := NatsOperationJournalCreateRequest{Key: key, Value: value, Authority: proof}
	return c.requestAsync(ctx, subject, request, proof)
}

// UpdateAsync mirrors the C# UpdateAsync.
func (c *NatsOperationJournalMutationClient) UpdateAsync(
	ctx context.Context,
	key string,
	value string,
	revision uint64,
) (NatsOperationJournalMutationReply, error) {
	if err := c.validate(); err != nil {
		return NatsOperationJournalMutationReply{}, err
	}
	subject, err := c.topology.OperationJournalUpdateSubject()
	if err != nil {
		return NatsOperationJournalMutationReply{}, err
	}

	proof := c.authority.Issue(c.topology.Cell, "update", key, revision, value)
	request := NatsOperationJournalUpdateRequest{Key: key, Value: value, Revision: revision, Authority: proof}
	return c.requestAsync(ctx, subject, request, proof)
}

// ReadRuntimeLifecycleAsync mirrors the C# ReadRuntimeLifecycleAsync.
func (c *NatsOperationJournalMutationClient) ReadRuntimeLifecycleAsync(
	ctx context.Context,
	cell string,
	key string,
) (NatsRuntimeLifecycleJournalReply, error) {
	if err := c.validate(); err != nil {
		return NatsRuntimeLifecycleJournalReply{}, err
	}
	if ctx == nil {
		return NatsRuntimeLifecycleJournalReply{}, errors.New("(Parameter 'ctx')")
	}
	deadline, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	for {
		if err := deadline.Err(); err != nil {
			return NatsRuntimeLifecycleJournalReply{}, err
		}

		requestId := randomNatsNonce()
		binding := RuntimeLifecycleNatsProtocol.ProofBinding(RuntimeLifecycleNatsProtocolReadAction,
			RuntimeLifecycleNatsProtocolSchemaVersion, cell, key, 0, 0, requestId, nil)
		request := NatsRuntimeLifecycleJournalReadRequest{
			SchemaVersion: RuntimeLifecycleNatsProtocolSchemaVersion,
			Cell:          cell,
			Key:           key,
			RequestId:     requestId,
			Authority:     c.authority.Issue(cell, RuntimeLifecycleNatsProtocolReadAction, key, 0, binding),
		}

		subject, err := RuntimeLifecycleNatsProtocol.Subject(cell, "read")
		if err != nil {
			return NatsRuntimeLifecycleJournalReply{}, err
		}

		response, err := c.requestRuntimeAsync(deadline, subject, cell, request, request.Authority)
		if err == nil {
			if response.SchemaVersion == RuntimeLifecycleNatsProtocolSchemaVersion &&
				response.Status == int(RuntimeLifecycleJournalReadStatusUnavailable) {
				if err := sleepContext(deadline, 100*time.Millisecond); err != nil {
					return NatsRuntimeLifecycleJournalReply{}, err
				}

				continue
			}

			return response, nil
		}

		if !errors.Is(err, context.DeadlineExceeded) && deadline.Err() == nil {
			if err := sleepContext(deadline, 100*time.Millisecond); err != nil {
				return NatsRuntimeLifecycleJournalReply{}, err
			}

			continue
		}

		return NatsRuntimeLifecycleJournalReply{}, err
	}
}

// WriteRuntimeLifecycleAsync mirrors the C# WriteRuntimeLifecycleAsync.
func (c *NatsOperationJournalMutationClient) WriteRuntimeLifecycleAsync(
	ctx context.Context,
	cell string,
	key string,
	expectedRevision uint64,
	checkpoint string,
) (NatsRuntimeLifecycleJournalReply, error) {
	if err := c.validate(); err != nil {
		return NatsRuntimeLifecycleJournalReply{}, err
	}
	if ctx == nil {
		return NatsRuntimeLifecycleJournalReply{}, errors.New("(Parameter 'ctx')")
	}
	action := RuntimeLifecycleNatsProtocolUpdateAction
	if expectedRevision == 0 {
		action = RuntimeLifecycleNatsProtocolCreateAction
	}

	requestId := randomNatsNonce()
	parsed, valid := RuntimeLifecycleNatsProtocol.TryDeserialize(checkpoint)
	if !valid {
		return NatsRuntimeLifecycleJournalReply{}, errors.New(
			"Runtime lifecycle checkpoint is not canonical. (Parameter 'checkpoint')")
	}

	binding := RuntimeLifecycleNatsProtocol.ProofBinding(action, RuntimeLifecycleNatsProtocolSchemaVersion,
		cell, key, expectedRevision, parsed.WriterEpoch.Value, requestId, &checkpoint)
	request := NatsRuntimeLifecycleJournalWriteRequest{
		SchemaVersion:    RuntimeLifecycleNatsProtocolSchemaVersion,
		Cell:             cell,
		Key:              key,
		ExpectedRevision: expectedRevision,
		WriterEpoch:      parsed.WriterEpoch.Value,
		Checkpoint:       checkpoint,
		RequestId:        requestId,
		Authority:        c.authority.Issue(cell, action, key, expectedRevision, binding),
	}

	subject, err := RuntimeLifecycleNatsProtocol.Subject(cell, "write")
	if err != nil {
		return NatsRuntimeLifecycleJournalReply{}, err
	}

	return c.requestRuntimeAsync(ctx, subject, cell, request, request.Authority)
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	if ctx == nil {
		return errors.New("(Parameter 'ctx')")
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *NatsOperationJournalMutationClient) requestAsync(
	ctx context.Context,
	subject string,
	request any,
	proof NatsOperationJournalMutationAuthorityProof,
) (NatsOperationJournalMutationReply, error) {
	if err := c.validate(); err != nil {
		return NatsOperationJournalMutationReply{}, err
	}
	replySubject, err := c.topology.OperationJournalReplySubject(c.authority.CallerIdentity, randomNatsNonce())
	if err != nil {
		return NatsOperationJournalMutationReply{}, err
	}

	response, err := natsRequestReplyOnce(ctx, c.client, subject, natsMarshalServicePayload(request), replySubject)
	if err != nil {
		return NatsOperationJournalMutationReply{}, err
	}

	var mutationReply NatsOperationJournalMutationReply
	if err := json.Unmarshal(response, &mutationReply); err != nil {
		return NatsOperationJournalMutationReply{}, errors.New(
			"The private journal mutation service returned no reply.")
	}

	requestDigest := NatsOperationJournalMutationRequestDigestCreate(proof)
	if mutationReply.RequestDigest != requestDigest {
		return NatsOperationJournalMutationReply{}, errors.New(
			"The private journal mutation service reply did not bind the exact request authority.")
	}

	if !c.replies.Verify(&mutationReply, requestDigest) {
		return NatsOperationJournalMutationReply{}, errors.New(
			"The private journal mutation service reply failed authority verification.")
	}

	return mutationReply, nil
}

func (c *NatsOperationJournalMutationClient) requestRuntimeAsync(
	ctx context.Context,
	subject string,
	cell string,
	request any,
	proof NatsOperationJournalMutationAuthorityProof,
) (NatsRuntimeLifecycleJournalReply, error) {
	if err := c.validate(); err != nil {
		return NatsRuntimeLifecycleJournalReply{}, err
	}
	replySubject, err := RuntimeLifecycleNatsProtocol.ReplySubject(cell, c.authority.CallerIdentity, randomNatsNonce())
	if err != nil {
		return NatsRuntimeLifecycleJournalReply{}, err
	}

	response, err := natsRequestReplyOnce(ctx, c.client, subject, natsMarshalServicePayload(request), replySubject)
	if err != nil {
		return NatsRuntimeLifecycleJournalReply{}, err
	}

	var runtimeReply NatsRuntimeLifecycleJournalReply
	if err := json.Unmarshal(response, &runtimeReply); err != nil {
		return NatsRuntimeLifecycleJournalReply{}, errors.New(
			"The private runtime lifecycle journal service returned no reply.")
	}

	if !c.replies.VerifyRuntime(&runtimeReply, NatsOperationJournalMutationRequestDigestCreate(proof)) {
		return NatsRuntimeLifecycleJournalReply{}, errors.New(
			"The private runtime lifecycle journal reply failed authority verification.")
	}

	return runtimeReply, nil
}

func (c *NatsOperationJournalMutationClient) validate() error {
	if c == nil {
		return errors.New("(Parameter 'client')")
	}
	if c.client == nil {
		return errors.New("(Parameter 'client')")
	}
	if c.topology == nil {
		return errors.New("(Parameter 'topology')")
	}
	if c.authority == nil {
		return errors.New("(Parameter 'authority')")
	}
	if c.replies == nil {
		return errors.New("(Parameter 'replies')")
	}
	return nil
}

// natsRequestReplyOnce implements the C# one-shot reply subscription: publish
// with an explicit reply subject, read exactly one reply, bounded by a
// 15-second window.
func natsRequestReplyOnce(
	ctx context.Context,
	client *nats.Conn,
	subject string,
	payload []byte,
	replySubject string,
) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("(Parameter 'ctx')")
	}
	if client == nil {
		return nil, errors.New("(Parameter 'client')")
	}
	deadline, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	replies := make(chan *nats.Msg, 1)
	subscription, err := client.ChanSubscribe(replySubject, replies)
	if err != nil {
		return nil, err
	}
	defer subscription.Unsubscribe()

	if err := client.Flush(); err != nil {
		return nil, err
	}

	if err := client.PublishMsg(&nats.Msg{Subject: subject, Reply: replySubject, Data: payload}); err != nil {
		return nil, err
	}

	select {
	case message := <-replies:
		if message == nil {
			return nil, errors.New("The private journal mutation service returned no reply.")
		}

		return message.Data, nil
	case <-deadline.Done():
		return nil, deadline.Err()
	}
}

// NatsOperationJournalCreateRequest mirrors the C# record.
type NatsOperationJournalCreateRequest struct {
	Key       string                                     `json:"Key"`
	Value     string                                     `json:"Value"`
	Authority NatsOperationJournalMutationAuthorityProof `json:"Authority"`
}

// NatsOperationJournalUpdateRequest mirrors the C# record.
type NatsOperationJournalUpdateRequest struct {
	Key       string                                     `json:"Key"`
	Value     string                                     `json:"Value"`
	Revision  uint64                                     `json:"Revision"`
	Authority NatsOperationJournalMutationAuthorityProof `json:"Authority"`
}

// NatsOperationJournalMutationReply mirrors the C# record.
type NatsOperationJournalMutationReply struct {
	Succeeded     bool   `json:"Succeeded"`
	Revision      uint64 `json:"Revision"`
	RequestDigest string `json:"RequestDigest"`
	Signature     string `json:"Signature"`
}

// Payload mirrors the C# Payload.
func (r NatsOperationJournalMutationReply) Payload() string {
	return strings.Join([]string{
		strconv.FormatBool(r.Succeeded),
		strconv.FormatUint(r.Revision, 10),
		r.RequestDigest,
	}, "|")
}

// NatsOperationJournalMutationAuthorityProof mirrors the C# record.
type NatsOperationJournalMutationAuthorityProof struct {
	Cell             string    `json:"Cell"`
	CallerIdentity   string    `json:"CallerIdentity"`
	Action           string    `json:"Action"`
	Key              string    `json:"Key"`
	Revision         uint64    `json:"Revision"`
	CiphertextDigest string    `json:"CiphertextDigest"`
	Lease            string    `json:"Lease"`
	ExpiresAt        time.Time `json:"ExpiresAt"`
	Nonce            string    `json:"Nonce"`
	Signature        string    `json:"Signature"`
}

// Payload mirrors the C# Payload.
func (p NatsOperationJournalMutationAuthorityProof) Payload() string {
	return strings.Join([]string{
		p.Cell,
		p.CallerIdentity,
		p.Action,
		p.Key,
		strconv.FormatUint(p.Revision, 10),
		p.CiphertextDigest,
		p.Lease,
		strconv.FormatInt(p.ExpiresAt.UTC().Unix(), 10),
		p.Nonce,
	}, "|")
}

// NatsOperationJournalMutationAuthoritySigner mirrors the C# class.
type NatsOperationJournalMutationAuthoritySigner struct {
	CallerIdentity string
	key            *ecdsa.PrivateKey
}

// NewNatsOperationJournalMutationAuthoritySigner mirrors the C# primary
// constructor.
func NewNatsOperationJournalMutationAuthoritySigner(
	callerIdentity string,
	key *ecdsa.PrivateKey,
) *NatsOperationJournalMutationAuthoritySigner {
	return &NatsOperationJournalMutationAuthoritySigner{CallerIdentity: callerIdentity, key: key}
}

// Issue mirrors the C# Issue.
func (s *NatsOperationJournalMutationAuthoritySigner) Issue(
	cell string,
	action string,
	keyName string,
	revision uint64,
	value string,
) NatsOperationJournalMutationAuthorityProof {
	digest := sha256.Sum256([]byte(value))
	callerIdentity := ""
	if s != nil {
		callerIdentity = s.CallerIdentity
	}
	proof := NatsOperationJournalMutationAuthorityProof{
		Cell:             cell,
		CallerIdentity:   callerIdentity,
		Action:           action,
		Key:              keyName,
		Revision:         revision,
		CiphertextDigest: hex.EncodeToString(digest[:]),
		Lease:            randomNatsNonce(),
		ExpiresAt:        time.Now().UTC().Add(2 * time.Minute),
		Nonce:            randomNatsNonce(),
		Signature:        "",
	}

	if s == nil || s.key == nil {
		return proof
	}
	signature, err := ecdsa.SignASN1(rand.Reader, s.key, sha256Sum(proofPayloadBytes(proof)))
	if err == nil {
		proof.Signature = base64.StdEncoding.EncodeToString(signature)
	}

	return proof
}

func proofPayloadBytes(p NatsOperationJournalMutationAuthorityProof) []byte {
	return []byte(p.Payload())
}

func sha256Sum(data []byte) []byte {
	digest := sha256.Sum256(data)
	return digest[:]
}

// NatsOperationJournalMutationAuthorityVerifier mirrors the C# class.
type NatsOperationJournalMutationAuthorityVerifier struct {
	publicKey []byte
}

// NewNatsOperationJournalMutationAuthorityVerifier mirrors the C# primary
// constructor.
func NewNatsOperationJournalMutationAuthorityVerifier(publicKey []byte) *NatsOperationJournalMutationAuthorityVerifier {
	copied := append([]byte(nil), publicKey...)
	return &NatsOperationJournalMutationAuthorityVerifier{publicKey: copied}
}

// Verify mirrors the C# Verify.
func (v *NatsOperationJournalMutationAuthorityVerifier) Verify(
	proof *NatsOperationJournalMutationAuthorityProof,
	cell string,
	callers map[string]struct{},
	action string,
	keyName string,
	revision uint64,
	value string,
) bool {
	if v == nil || proof == nil {
		return false
	}

	digest := sha256.Sum256([]byte(value))
	_, callerKnown := callers[proof.CallerIdentity]
	if proof.Cell != cell || !callerKnown || proof.Action != action ||
		proof.Key != keyName || proof.Revision != revision ||
		proof.CiphertextDigest != hex.EncodeToString(digest[:]) ||
		strings.TrimSpace(proof.Lease) == "" || strings.TrimSpace(proof.Nonce) == "" ||
		!proof.ExpiresAt.After(time.Now().UTC()) ||
		proof.ExpiresAt.After(time.Now().UTC().Add(5*time.Minute)) {
		return false
	}

	parsed, err := x509.ParsePKIXPublicKey(v.publicKey)
	if err != nil {
		return false
	}

	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || !natsJournalIsP256(key) {
		return false
	}

	signature, err := base64.StdEncoding.DecodeString(proof.Signature)
	if err != nil {
		return false
	}

	return ecdsa.VerifyASN1(key, sha256Sum([]byte(proof.Payload())), signature)
}

// NatsOperationJournalMutationRequestDigest mirrors the C# static class.
var NatsOperationJournalMutationRequestDigest natsOperationJournalMutationRequestDigest

type natsOperationJournalMutationRequestDigest struct{}

// NatsOperationJournalMutationRequestDigestCreate mirrors the C# Create.
func NatsOperationJournalMutationRequestDigestCreate(
	proof NatsOperationJournalMutationAuthorityProof,
) string {
	material := proof.Payload() + "|" + proof.Signature
	return hex.EncodeToString(sha256Sum([]byte(material)))
}

// NatsOperationJournalMutationReplySigner mirrors the C# class.
type NatsOperationJournalMutationReplySigner struct {
	key *ecdsa.PrivateKey
}

// NatsOperationJournalMutationReplySignerLoad mirrors the C# Load.
func NatsOperationJournalMutationReplySignerLoad(path string) (*NatsOperationJournalMutationReplySigner, error) {
	_, data, err := natsJournalReadFile(path, 8192, true)
	if err != nil {
		return nil, errors.New("The reply signing key file is unavailable.")
	}
	defer clear(data)

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("The reply signing key is not valid PEM.")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes); ecErr == nil {
			key = ecKey
		} else {
			return nil, err
		}
	}

	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok || privateKey == nil || !natsJournalIsP256(&privateKey.PublicKey) {
		return nil, errors.New("The reply signing key is not an ECDSA key.")
	}

	return &NatsOperationJournalMutationReplySigner{key: privateKey}, nil
}

// Sign mirrors the C# Sign.
func (s *NatsOperationJournalMutationReplySigner) Sign(
	succeeded bool,
	revision uint64,
	requestDigest string,
) NatsOperationJournalMutationReply {
	reply := NatsOperationJournalMutationReply{
		Succeeded:     succeeded,
		Revision:      revision,
		RequestDigest: requestDigest,
		Signature:     "",
	}

	if s == nil || s.key == nil {
		return reply
	}
	if signature, err := ecdsa.SignASN1(rand.Reader, s.key, sha256Sum([]byte(reply.Payload()))); err == nil {
		reply.Signature = base64.StdEncoding.EncodeToString(signature)
	}

	return reply
}

// SignRuntime mirrors the C# SignRuntime.
func (s *NatsOperationJournalMutationReplySigner) SignRuntime(
	status int,
	revision uint64,
	checkpoint *string,
	requestDigest string,
) NatsRuntimeLifecycleJournalReply {
	reply := NatsRuntimeLifecycleJournalReply{
		SchemaVersion: RuntimeLifecycleNatsProtocolSchemaVersion,
		Status:        status,
		Revision:      revision,
		Checkpoint:    checkpoint,
		RequestDigest: requestDigest,
		Signature:     "",
	}

	if s == nil || s.key == nil {
		return reply
	}
	if signature, err := ecdsa.SignASN1(rand.Reader, s.key, sha256Sum([]byte(reply.Payload()))); err == nil {
		reply.Signature = base64.StdEncoding.EncodeToString(signature)
	}

	return reply
}

// ExportPublicKey mirrors the C# ExportPublicKey.
func (s *NatsOperationJournalMutationReplySigner) ExportPublicKey() ([]byte, error) {
	if s == nil || s.key == nil {
		return nil, errors.New("The reply signing key is unavailable.")
	}
	return x509.MarshalPKIXPublicKey(&s.key.PublicKey)
}

// Dispose mirrors the C# Dispose.
func (s *NatsOperationJournalMutationReplySigner) Dispose() {}

// NatsOperationJournalMutationReplyVerifier mirrors the C# class.
type NatsOperationJournalMutationReplyVerifier struct {
	publicKey []byte
}

// NewNatsOperationJournalMutationReplyVerifier mirrors the C# primary
// constructor.
func NewNatsOperationJournalMutationReplyVerifier(publicKey []byte) *NatsOperationJournalMutationReplyVerifier {
	copied := append([]byte(nil), publicKey...)
	return &NatsOperationJournalMutationReplyVerifier{publicKey: copied}
}

// Verify mirrors the C# Verify.
func (v *NatsOperationJournalMutationReplyVerifier) Verify(
	reply *NatsOperationJournalMutationReply,
	requestDigest string,
) bool {
	if reply == nil || reply.RequestDigest != requestDigest ||
		strings.TrimSpace(reply.Signature) == "" {
		return false
	}

	return v.verifySignature(sha256Sum([]byte(reply.Payload())), reply.Signature)
}

// VerifyRuntime mirrors the C# VerifyRuntime.
func (v *NatsOperationJournalMutationReplyVerifier) VerifyRuntime(
	reply *NatsRuntimeLifecycleJournalReply,
	requestDigest string,
) bool {
	if reply == nil || reply.SchemaVersion != RuntimeLifecycleNatsProtocolSchemaVersion ||
		reply.RequestDigest != requestDigest ||
		strings.TrimSpace(reply.Signature) == "" {
		return false
	}

	return v.verifySignature(sha256Sum([]byte(reply.Payload())), reply.Signature)
}

func (v *NatsOperationJournalMutationReplyVerifier) verifySignature(digest []byte, signature string) bool {
	if v == nil {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(v.publicKey)
	if err != nil {
		return false
	}

	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || !natsJournalIsP256(key) {
		return false
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}

	return ecdsa.VerifyASN1(key, digest, signatureBytes)
}

func natsJournalIsP256(key *ecdsa.PublicKey) bool {
	return key != nil && key.Curve != nil && key.Curve.Params().Name == elliptic.P256().Params().Name
}

// The following section maps the NATS.Net services API (NatsSvcConfig,
// INatsSvcServer, AddEndpointAsync) onto plain nats.go subscriptions. There is
// no C# source file: it is the client-library mapping every Messaging service
// runtime shares. Endpoints are queue-grouped request handlers; the $SRV
// discovery subjects answer with the NATS.Net micro-service wire shape so the
// C# HasExpectedEndpoint verification logic is unchanged.

type natsSvcConfig struct {
	Name        string
	Version     string
	Description string
	Metadata    map[string]string
	QueueGroup  string
}

type natsSvcEndpointConfig struct {
	Name       string
	Subject    string
	QueueGroup string
	Metadata   map[string]string
	Handler    func(context.Context, *nats.Msg) error
}

type natsSvcServer struct {
	client        *nats.Conn
	config        natsSvcConfig
	endpoints     []natsSvcEndpointConfig
	subscriptions []*nats.Subscription
	started       bool
	mu            sync.Mutex
}

func newNatsSvcServer(client *nats.Conn, config natsSvcConfig) *natsSvcServer {
	return &natsSvcServer{client: client, config: config}
}

func (s *natsSvcServer) AddEndpoint(config natsSvcEndpointConfig) error {
	if s == nil {
		return errors.New("NATS service is unavailable.")
	}
	if config.Handler == nil {
		return errors.New("NATS service endpoint handler is required.")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if config.QueueGroup == "" {
		config.QueueGroup = s.config.QueueGroup
	}

	s.endpoints = append(s.endpoints, config)
	return nil
}

func (s *natsSvcServer) Start(ctx context.Context) error {
	if s == nil {
		return errors.New("NATS service is unavailable.")
	}
	if ctx == nil {
		return errors.New("(Parameter 'ctx')")
	}
	if s.client == nil {
		return errors.New("NATS service client is unavailable.")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return nil
	}

	for _, endpoint := range s.endpoints {
		endpoint := endpoint
		handler := func(message *nats.Msg) {
			if err := endpoint.Handler(ctx, message); err != nil {
				// The instrumentation wrapper at the call site records errors;
				// the service itself keeps serving.
				_ = err
			}
		}

		var subscription *nats.Subscription
		var err error
		if endpoint.QueueGroup != "" {
			subscription, err = s.client.QueueSubscribe(endpoint.Subject, endpoint.QueueGroup, handler)
		} else {
			subscription, err = s.client.Subscribe(endpoint.Subject, handler)
		}

		if err != nil {
			s.stopLocked()
			return err
		}

		s.subscriptions = append(s.subscriptions, subscription)
	}

	s.subscriptions = append(s.subscriptions, s.subscribeDiscovery("$SRV.PING")...)
	s.started = true
	return s.client.Flush()
}

func (s *natsSvcServer) subscribeDiscovery(subject string) []*nats.Subscription {
	subscription, err := s.client.Subscribe(subject, func(message *nats.Msg) {
		_ = message.Respond(s.discoveryDocument())
	})
	if err != nil {
		return nil
	}

	return []*nats.Subscription{subscription}
}

type natsSvcEndpointInfo struct {
	Name       string            `json:"name"`
	Subject    string            `json:"subject"`
	QueueGroup string            `json:"queue_group"`
	Metadata   map[string]string `json:"metadata"`
}

type natsSvcDiscoveryDocument struct {
	Type        string                `json:"type"`
	Id          string                `json:"id"`
	Name        string                `json:"name"`
	Version     string                `json:"version"`
	Description string                `json:"description"`
	Endpoints   []natsSvcEndpointInfo `json:"endpoints"`
}

func (s *natsSvcServer) discoveryDocument() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	endpoints := make([]natsSvcEndpointInfo, 0, len(s.endpoints))
	for _, endpoint := range s.endpoints {
		endpoints = append(endpoints, natsSvcEndpointInfo{
			Name:       endpoint.Name,
			Subject:    endpoint.Subject,
			QueueGroup: endpoint.QueueGroup,
			Metadata:   endpoint.Metadata,
		})
	}

	document := natsSvcDiscoveryDocument{
		Type:        "io.nats.micro.v1.info_response",
		Id:          s.config.Name,
		Name:        s.config.Name,
		Version:     s.config.Version,
		Description: s.config.Description,
		Endpoints:   endpoints,
	}

	encoded, err := json.Marshal(document)
	if err != nil {
		return []byte("{}")
	}

	return encoded
}

func (s *natsSvcServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.stopLocked()
}

func (s *natsSvcServer) stopLocked() {
	for _, subscription := range s.subscriptions {
		_ = subscription.Drain()
	}

	s.subscriptions = nil
	s.started = false
}
