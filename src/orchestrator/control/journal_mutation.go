package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

// NatsOperationJournalMutationService is the private typed mutation boundary.
// Only this service holds journal KV write credentials.
type NatsOperationJournalMutationService struct {
	service  *natsSvcServer
	replies  *NatsOperationJournalMutationReplySigner
	lifetime context.CancelFunc
}

// NatsOperationJournalMutationServiceStartAsync starts the private mutation service.
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

// Dispose stops the service and releases its signer.
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
	envelope, err := unmarshalJournalEnvelope(
		message.Data, message.Subject, journalPayloadOperationCreate, &request)
	if err != nil || !journalEnvelopeBindsProof(envelope, request.Authority) {
		return nil
	}

	if request.SchemaVersion != protocol.ProtocolVersion.Current() ||
		!natsOperationJournalIsValid(request.Key, request.Value) ||
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
	envelope, err := unmarshalJournalEnvelope(
		message.Data, message.Subject, journalPayloadOperationUpdate, &request)
	if err != nil || !journalEnvelopeBindsProof(envelope, request.Authority) {
		return nil
	}

	if request.SchemaVersion != protocol.ProtocolVersion.Current() ||
		!natsOperationJournalIsValid(request.Key, request.Value) || request.Revision == 0 ||
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

func natsOperationJournalReply(
	ctx context.Context,
	message *nats.Msg,
	authority NatsOperationJournalMutationAuthorityProof,
	succeeded bool,
	revision uint64,
	replies *NatsOperationJournalMutationReplySigner,
) error {
	digest := NatsOperationJournalMutationRequestDigestCreate(authority)
	reply := replies.Sign(succeeded, revision, digest)
	document, err := marshalJournalEnvelope(
		message.Reply,
		journalPayloadOperationReply,
		authority.Cell,
		"journal-writer",
		authority.Nonce+"-reply",
		digest,
		authority.Nonce,
		reply,
	)
	if err != nil {
		return err
	}
	return message.Respond(document)
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
	envelope, err := unmarshalJournalEnvelope(
		message.Data, message.Subject, journalPayloadRuntimeRead, &request)
	if err != nil || !journalEnvelopeBindsProof(envelope, request.Authority) {
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
	envelope, err := unmarshalJournalEnvelope(
		message.Data, message.Subject, journalPayloadRuntimeWrite, &request)
	if err != nil || !journalEnvelopeBindsProof(envelope, request.Authority) {
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
	digest := NatsOperationJournalMutationRequestDigestCreate(authority)
	document, err := marshalJournalEnvelope(
		message.Reply,
		journalPayloadRuntimeReply,
		authority.Cell,
		"journal-writer",
		authority.Nonce+"-reply",
		digest,
		authority.Nonce,
		reply,
	)
	if err != nil {
		return err
	}
	return message.Respond(document)
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

// NatsOperationJournalMutationClient calls the private mutation service.
type NatsOperationJournalMutationClient struct {
	client    *nats.Conn
	topology  *NatsTopology
	authority *NatsOperationJournalMutationAuthoritySigner
	replies   *NatsOperationJournalMutationReplyVerifier
}

// NewNatsOperationJournalMutationClient creates a mutation client.
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

// CreateAsync creates a journal value through the private mutation service.
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
	request := NatsOperationJournalCreateRequest{SchemaVersion: protocol.ProtocolVersion.Current(), Key: key, Value: value, Authority: proof}
	return c.requestAsync(ctx, subject, request, proof)
}

// UpdateAsync conditionally updates a journal value.
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
	request := NatsOperationJournalUpdateRequest{SchemaVersion: protocol.ProtocolVersion.Current(), Key: key, Value: value, Revision: revision, Authority: proof}
	return c.requestAsync(ctx, subject, request, proof)
}

// ReadRuntimeLifecycleAsync reads a lifecycle checkpoint through the private service.
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

// WriteRuntimeLifecycleAsync conditionally writes a lifecycle checkpoint.
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

	requestDigest := NatsOperationJournalMutationRequestDigestCreate(proof)
	document, err := marshalJournalEnvelope(
		subject,
		journalPayloadTypeForOperation(request),
		c.topology.Cell,
		proof.CallerIdentity,
		proof.Nonce,
		requestDigest,
		"",
		request,
	)
	if err != nil {
		return NatsOperationJournalMutationReply{}, err
	}
	response, err := natsRequestReplyOnce(ctx, c.client, subject, document, replySubject)
	if err != nil {
		return NatsOperationJournalMutationReply{}, err
	}

	var mutationReply NatsOperationJournalMutationReply
	envelope, err := unmarshalJournalEnvelope(
		response, replySubject, journalPayloadOperationReply, &mutationReply)
	if err != nil || !journalReplyEnvelopeBindsProof(envelope, proof) {
		return NatsOperationJournalMutationReply{}, errors.New(
			"The private journal mutation service returned no reply.")
	}

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

	requestDigest := NatsOperationJournalMutationRequestDigestCreate(proof)
	document, err := marshalJournalEnvelope(
		subject,
		journalPayloadTypeForRuntime(request),
		c.topology.Cell,
		proof.CallerIdentity,
		proof.Nonce,
		requestDigest,
		"",
		request,
	)
	if err != nil {
		return NatsRuntimeLifecycleJournalReply{}, err
	}
	response, err := natsRequestReplyOnce(ctx, c.client, subject, document, replySubject)
	if err != nil {
		return NatsRuntimeLifecycleJournalReply{}, err
	}

	var runtimeReply NatsRuntimeLifecycleJournalReply
	envelope, err := unmarshalJournalEnvelope(
		response, replySubject, journalPayloadRuntimeReply, &runtimeReply)
	if err != nil || !journalReplyEnvelopeBindsProof(envelope, proof) {
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

// natsRequestReplyOnce publishes with an explicit reply subject and reads one
// reply within a 15-second window.
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
	if err := deadline.Err(); err != nil {
		return nil, err
	}

	replies := make(chan *nats.Msg, 1)
	subscription, err := client.ChanSubscribe(replySubject, replies)
	if err != nil {
		return nil, err
	}
	defer subscription.Unsubscribe()

	if err := deadline.Err(); err != nil {
		return nil, err
	}
	if err := client.Flush(); err != nil {
		return nil, err
	}

	if err := deadline.Err(); err != nil {
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

func sha256Sum(data []byte) []byte {
	digest := sha256.Sum256(data)
	return digest[:]
}

// NatsOperationJournalMutationReplySigner signs mutation replies.
type NatsOperationJournalMutationReplySigner struct {
	key *ecdsa.PrivateKey
}

// NatsOperationJournalMutationReplySignerLoad loads a reply signing key.
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

// Sign creates a signed operation-journal reply.
func (s *NatsOperationJournalMutationReplySigner) Sign(
	succeeded bool,
	revision uint64,
	requestDigest string,
) NatsOperationJournalMutationReply {
	reply := NatsOperationJournalMutationReply{
		SchemaVersion: protocol.ProtocolVersion.Current(),
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

// SignRuntime creates a signed lifecycle-journal reply.
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

// ExportPublicKey returns the signer's PKIX public key.
func (s *NatsOperationJournalMutationReplySigner) ExportPublicKey() ([]byte, error) {
	if s == nil || s.key == nil {
		return nil, errors.New("The reply signing key is unavailable.")
	}
	return x509.MarshalPKIXPublicKey(&s.key.PublicKey)
}

// Dispose releases signer resources.
func (s *NatsOperationJournalMutationReplySigner) Dispose() {}

// NatsOperationJournalMutationReplyVerifier verifies signed journal replies.
type NatsOperationJournalMutationReplyVerifier struct {
	publicKey []byte
}

// NewNatsOperationJournalMutationReplyVerifier creates a reply verifier.
func NewNatsOperationJournalMutationReplyVerifier(publicKey []byte) *NatsOperationJournalMutationReplyVerifier {
	copied := append([]byte(nil), publicKey...)
	return &NatsOperationJournalMutationReplyVerifier{publicKey: copied}
}

// Verify checks an operation-journal reply and its request binding.
func (v *NatsOperationJournalMutationReplyVerifier) Verify(
	reply *NatsOperationJournalMutationReply,
	requestDigest string,
) bool {
	if reply == nil || reply.SchemaVersion != protocol.ProtocolVersion.Current() ||
		reply.RequestDigest != requestDigest ||
		strings.TrimSpace(reply.Signature) == "" {
		return false
	}

	return v.verifySignature(sha256Sum([]byte(reply.Payload())), reply.Signature)
}

// VerifyRuntime checks a lifecycle-journal reply and its request binding.
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

// The service adapter maps the NATS micro-service protocol onto nats.go
// subscriptions. Endpoints are queue-grouped request handlers, and the $SRV
// discovery subjects return the standard micro-service wire shape.

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
