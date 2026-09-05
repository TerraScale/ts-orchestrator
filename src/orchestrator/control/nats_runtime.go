package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/contracts"
	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
	"terrascale.tech/orchestrator/src/orchestrator/control/internal/shared"
	"terrascale.tech/orchestrator/src/orchestrator/control/messaging"
	"terrascale.tech/orchestrator/src/orchestrator/natspolicy"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

const (
	natsRuntimeConnectTimeout        = 15 * time.Second
	natsRuntimeCheckTimeout          = 15 * time.Second
	natsRuntimeProofTimeout          = 5 * time.Second
	natsRuntimeCommandValidityWindow = 10 * time.Minute
)

// NatsRuntime is the regional controller composition. Topology is read-only
// here: infrastructure provisions it, while the controller opens and checks
// every resource before it starts serving or claiming membership.
type NatsRuntime struct {
	client             *nats.Conn
	topology           *NatsTopology
	service            *shared.NatsSvcServer
	serviceInfo        *nats.Subscription
	authority          *RegionalAuthorityCoordinator
	membership         *RegionalRuntimeMembership
	membershipIdentity *RegionalRuntimeMembershipIdentity
	stats              *NatsServiceEndpointStats
	commandIngress     *NatsCommandIngress

	lifetimeCtx    context.Context
	cancel         context.CancelFunc
	completion     chan struct{}
	completionOnce sync.Once
	closeOnce      sync.Once
	closed         int32
	closeErr       error
}

type natsRuntimeState struct {
	leaders       jetstream.KeyValue
	runtime       jetstream.KeyValue
	delivery      jetstream.KeyValue
	operations    jetstream.KeyValue
	proofs        jetstream.KeyValue
	bundles       jetstream.ObjectStore
	protocol      jetstream.ObjectStore
	startup       jetstream.Consumer
	cellSpec      jetstream.Consumer
	commandReplay jetstream.KeyValue
}

// NatsRuntimeStartAsync composes a regional run runtime. Check is deliberately
// kept separate so it cannot accidentally leave a goroutine or service alive.
func NatsRuntimeStartAsync(ctx context.Context, options *OrchestratorOptions) (*NatsRuntime, error) {
	if err := validateNatsRuntimeInputs(ctx, options, OrchestratorCommandRun); err != nil {
		return nil, err
	}

	identity, err := directory.RegionalRuntimeMembershipIdentityLoadFile(options.MembershipSigningKeyFile)
	if err != nil {
		return nil, err
	}
	identityTransferred := false
	defer func() {
		if !identityTransferred {
			identity.Dispose()
		}
	}()
	pins, err := directory.RegionalRuntimeMembershipPinsLoadFile(options.MembershipPinsFile)
	if err != nil {
		return nil, err
	}
	if pins[options.Instance] != identity.PublicKey {
		return nil, errors.New("membership pins do not admit the controller signing identity")
	}

	lifetimeCtx, cancel := context.WithCancel(ctx)
	client, err := natsRuntimeConnect(options)
	if err != nil {
		cancel()
		return nil, err
	}
	topology := NewNatsTopology(options.Cell, options.Replicas, options.Instance)
	cleanup := func() {
		cancel()
		client.Close()
	}

	operationCtx, operationCancel := natsRuntimeBoundedContext(lifetimeCtx, natsRuntimeCheckTimeout)
	defer operationCancel()
	state, err := natsRuntimeOpenAndValidate(operationCtx, client, topology)
	if err != nil {
		cleanup()
		return nil, err
	}
	if err := natsRuntimeVerifyProtocol(operationCtx, state.protocol, topology); err != nil {
		cleanup()
		return nil, err
	}
	if err := natsRuntimeVerifyDurableProof(operationCtx, state.startup, topology, client); err != nil {
		cleanup()
		return nil, err
	}

	authority, err := RegionalAuthorityCoordinatorStartAsync(
		lifetimeCtx, state.leaders, topology.Cell, topology.Instance)
	if err != nil {
		cleanup()
		return nil, err
	}
	startedAt := time.Now().UTC()
	capabilities := []string{
		"authority", "authority-election", "delivery", "messaging", "observability",
		"operator-read", "provider-ownership", "reconciliation", "regional-membership",
		"runtime", "scheduler", "security", "service-discovery", "storage", "terrabase",
		"nats-nkey-authenticated", "nats-mtls",
	}
	sort.Strings(capabilities)
	membership, err := RegionalRuntimeMembershipStartAsync(
		lifetimeCtx, state.runtime, topology, "unknown", capabilities, startedAt,
		authority.Snapshot, identity, pins)
	if err != nil {
		authority.Dispose()
		cleanup()
		return nil, err
	}

	runtime := &NatsRuntime{
		client: client, topology: topology, authority: authority, membership: membership, membershipIdentity: identity,
		stats: NewNatsServiceEndpointStats(), lifetimeCtx: lifetimeCtx, cancel: cancel,
		completion: make(chan struct{}),
	}
	identityTransferred = true
	if err := runtime.startCommandIngress(options, state); err != nil {
		_ = runtime.Close()
		return nil, err
	}
	if err := runtime.startService(); err != nil {
		_ = runtime.Close()
		return nil, err
	}

	go func() {
		select {
		case <-ctx.Done():
			_ = runtime.Close()
		case <-authority.Completion():
			// A component exiting is terminal for this composition. Close the
			// service, membership, authority, and client immediately so callers
			// cannot observe a completed runtime while its transport is still
			// serving requests.
			_ = runtime.Close()
		case <-membership.Completion():
			_ = runtime.Close()
		case <-runtime.lifetimeCtx.Done():
		}
	}()
	return runtime, nil
}

// NatsRuntimeCheckAsync performs bounded, read-only topology and protocol
// validation. It intentionally does not start authority, membership, or a
// service and therefore leaves no runtime goroutine behind.
func NatsRuntimeCheckAsync(ctx context.Context, options *OrchestratorOptions) error {
	if err := validateNatsRuntimeInputs(ctx, options, OrchestratorCommandCheck); err != nil {
		return err
	}
	client, err := natsRuntimeConnect(options)
	if err != nil {
		return err
	}
	defer client.Close()
	topology := NewNatsTopology(options.Cell, options.Replicas, options.Instance)
	checkCtx, cancel := natsRuntimeBoundedContext(ctx, natsRuntimeCheckTimeout)
	defer cancel()
	state, err := natsRuntimeOpenAndValidate(checkCtx, client, topology)
	if err != nil {
		return err
	}
	if err := natsRuntimeVerifyProtocol(checkCtx, state.protocol, topology); err != nil {
		return err
	}
	return natsRuntimeVerifyDurableProof(checkCtx, state.startup, topology, client)
}

// NatsRuntimeCheck is the synchronous spelling used by command dispatchers.
func NatsRuntimeCheck(ctx context.Context, options *OrchestratorOptions) error {
	return NatsRuntimeCheckAsync(ctx, options)
}

func validateNatsRuntimeInputs(ctx context.Context, options *OrchestratorOptions, command OrchestratorCommand) error {
	if ctx == nil {
		return errors.New("a context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if options == nil {
		return errors.New("Orchestrator options are required.")
	}
	if options.Command != command {
		return fmt.Errorf("only the %s command can compose the regional NATS runtime", command.String())
	}
	if strings.TrimSpace(options.Cell) == "" || !shared.MessagingCellTokenIsValid(options.Cell) {
		return errors.New("The regional NATS cell is invalid.")
	}
	if options.Replicas != 1 && options.Replicas != 3 && options.Replicas != 5 {
		return errors.New("The regional NATS replica count is invalid.")
	}
	if strings.TrimSpace(options.Instance) == "" || !shared.MessagingCellTokenIsValid(options.Instance) {
		return errors.New("The regional NATS instance is invalid.")
	}
	if strings.TrimSpace(options.NatsURL) == "" {
		return errors.New("The regional NATS URL is required.")
	}
	parsedURL, err := url.Parse(options.NatsURL)
	if err != nil || parsedURL.Host == "" || (parsedURL.Scheme != "nats" && parsedURL.Scheme != "tls") {
		return errors.New("The regional NATS URL must be an absolute nats:// or tls:// URL.")
	}
	if (options.NatsNKeyFile == nil) != (options.NatsTls == nil) {
		return errors.New("Regional controller NKey and mTLS credentials must be supplied together.")
	}
	if command == OrchestratorCommandRun {
		if options.NatsNKeyFile == nil || options.NatsTls == nil || !strings.HasPrefix(options.NatsURL, "tls://") {
			return errors.New("The run command requires a tls:// regional control NATS URL, a private NKey seed, and complete mTLS credentials.")
		}
		if options.CommandIdentity == nil || options.CommandIdentity.SigningKeyFile == "" || len(options.CommandIdentity.TrustKeyFiles) == 0 {
			return errors.New("The run command requires command signing and trust key credentials.")
		}
		if options.Delivery == nil {
			return errors.New("The run command requires a signed delivery runtime.")
		}
		if options.MembershipSigningKeyFile == "" || options.MembershipPinsFile == "" {
			return errors.New("The run command requires membership signing identity and explicit peer pins.")
		}
		if options.CommandAggregateID != "" && options.CommandAggregateID != "delivery" {
			return errors.New("The run command aggregate must be delivery.")
		}
		if err := options.Delivery.Validate(); err != nil {
			return err
		}
	}
	if options.NatsNKeyFile != nil {
		if strings.TrimSpace(*options.NatsNKeyFile) == "" {
			return errors.New("The regional controller NKey seed file is required.")
		}
		if _, err := NatsCredentialFile.PublicKey(*options.NatsNKeyFile); err != nil {
			return errors.New("The regional controller NKey seed is invalid.")
		}
	}
	if options.NatsTls != nil {
		if _, err := NatsTlsFilesResolve(options.NatsTls.CaFile, options.NatsTls.CertificateFile, options.NatsTls.KeyFile, "TS_ORCH_NATS_TLS"); err != nil {
			return err
		}
	}
	return nil
}

func natsRuntimeConnect(options *OrchestratorOptions) (*nats.Conn, error) {
	connectionOptions := []nats.Option{
		nats.Timeout(natsRuntimeConnectTimeout),
		nats.MaxReconnects(0),
		nats.RetryOnFailedConnect(false),
		func(options *nats.Options) error {
			options.NoRandomize = true
			return nil
		},
	}
	if options.NatsNKeyFile != nil {
		connectionOptions = append(connectionOptions, NatsNkeyOption(*options.NatsNKeyFile))
	}
	if options.NatsTls != nil {
		connectionOptions = append(connectionOptions, options.NatsTls.Options()...)
	}
	return nats.Connect(options.NatsURL, connectionOptions...)
}

func natsRuntimeBoundedContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}

func natsRuntimeOpenAndValidate(ctx context.Context, client *nats.Conn, topology *NatsTopology) (*natsRuntimeState, error) {
	if client == nil || topology == nil {
		return nil, errors.New("NATS client and topology are required.")
	}
	js, err := jetstream.New(client)
	if err != nil {
		return nil, err
	}
	streams, err := topology.Streams()
	if err != nil {
		return nil, err
	}
	for _, expected := range streams {
		stream, err := js.Stream(ctx, expected.Name)
		if err != nil {
			return nil, err
		}
		info, err := stream.Info(ctx)
		if err != nil {
			return nil, err
		}
		if err := NatsOperationJournalStore.ValidateExactStreamConfiguration(info.Config, expected); err != nil {
			return nil, err
		}
	}
	openPlain := func(configuration jetstream.KeyValueConfig) (jetstream.KeyValue, error) {
		store, err := js.KeyValue(ctx, configuration.Bucket)
		if err != nil {
			return nil, err
		}
		stream, err := js.Stream(ctx, "KV_"+configuration.Bucket)
		if err != nil {
			return nil, err
		}
		info, err := stream.Info(ctx)
		if err != nil {
			return nil, err
		}
		if err := NatsOperationJournalStore.ValidatePlainTopologyKeyValueConfiguration(info.Config, configuration); err != nil {
			return nil, err
		}
		return store, nil
	}
	leaders, err := openPlain(topology.Leaders())
	if err != nil {
		return nil, err
	}
	runtimeStore, err := openPlain(topology.Runtime())
	if err != nil {
		return nil, err
	}
	delivery, err := openPlain(topology.Delivery())
	if err != nil {
		return nil, err
	}
	commandReplay, err := openPlain(topology.CommandReplay())
	if err != nil {
		return nil, err
	}
	operations, err := NatsOperationJournalStore.OpenAsync(ctx, js, topology.Operations(), client)
	if err != nil {
		return nil, err
	}
	proofs, err := NatsOperationJournalStore.OpenAsync(ctx, js, topology.OperationProofConsumptions(), client)
	if err != nil {
		return nil, err
	}
	openObject := func(configuration jetstream.ObjectStoreConfig) (jetstream.ObjectStore, error) {
		store, err := js.ObjectStore(ctx, configuration.Bucket)
		if err != nil {
			return nil, err
		}
		stream, err := js.Stream(ctx, "OBJ_"+configuration.Bucket)
		if err != nil {
			return nil, err
		}
		info, err := stream.Info(ctx)
		if err != nil {
			return nil, err
		}
		if err := NatsOperationJournalStore.ValidateExactObjectConfiguration(info.Config, configuration); err != nil {
			return nil, err
		}
		return store, nil
	}
	bundles, err := openObject(topology.Bundles())
	if err != nil {
		return nil, err
	}
	protocolStore, err := openObject(topology.ProtocolPackage())
	if err != nil {
		return nil, err
	}
	openConsumer := func(streamName string, expected jetstream.ConsumerConfig) (jetstream.Consumer, error) {
		stream, err := js.Stream(ctx, streamName)
		if err != nil {
			return nil, err
		}
		consumer, err := stream.Consumer(ctx, expected.Name)
		if err != nil {
			return nil, err
		}
		info, err := consumer.Info(ctx)
		if err != nil {
			return nil, err
		}
		if !NatsConsumerProfileMatches(info, expected, streamName) {
			return nil, errors.New("An infrastructure-provisioned NATS consumer does not match its closed profile.")
		}
		return consumer, nil
	}
	startupConfig, err := topology.StartupConsumer()
	if err != nil {
		return nil, err
	}
	startup, err := openConsumer("CELL_EVENTS", startupConfig)
	if err != nil {
		return nil, err
	}
	cellSpecConfig, err := topology.CellSpecConsumer()
	if err != nil {
		return nil, err
	}
	cellSpec, err := openConsumer("CELL_SPEC", cellSpecConfig)
	if err != nil {
		return nil, err
	}
	return &natsRuntimeState{leaders: leaders, runtime: runtimeStore, delivery: delivery,
		operations: operations, proofs: proofs, bundles: bundles, protocol: protocolStore,
		startup: startup, cellSpec: cellSpec, commandReplay: commandReplay}, nil
}

func natsRuntimeVerifyProtocol(ctx context.Context, store jetstream.ObjectStore, topology *NatsTopology) error {
	stored, err := store.GetBytes(ctx, topology.ProtocolObject())
	if err != nil {
		return err
	}
	if !bytes.Equal(stored, NatsProtocolPackageBytes) {
		return errors.New("NATS protocol package failed its integrity check.")
	}
	return nil
}

// sha256CommandPayloadDigestVerifier is the production protocol digest
// verifier. It is local to control composition so the runtime cannot be
// started with a permissive test implementation.
type sha256CommandPayloadDigestVerifier struct{}

func (sha256CommandPayloadDigestVerifier) Verify(payload protocol.OpaquePayload, expected protocol.PayloadDigest) protocol.VerificationOutcome {
	digest := sha256.Sum256(payload.Bytes())
	actual, ok := protocol.PayloadDigestTryCopyFrom(digest[:])
	if !ok || !expected.Equal(actual) {
		return protocol.VerificationOutcomeInvalid
	}
	return protocol.VerificationOutcomeValid
}

func (r *NatsRuntime) startCommandIngress(options *OrchestratorOptions, state *natsRuntimeState) error {
	if r == nil || r.client == nil || r.topology == nil {
		return errors.New("command ingress runtime composition is incomplete")
	}
	if options == nil || options.CommandIdentity == nil || options.CommandIdentity.SigningKeyFile == "" || len(options.CommandIdentity.TrustKeyFiles) == 0 {
		return errors.New("signed command ingress identity is missing")
	}
	if state == nil || state.commandReplay == nil || options.Delivery == nil {
		return errors.New("signed delivery runtime or replay store is missing")
	}
	if options.CommandAggregateID != "" && options.CommandAggregateID != "delivery" {
		return errors.New("signed command ingress aggregate must be delivery")
	}
	if r.client.MaxPayload() < messaging.DeliveryOperationMaxMessageBytes {
		return errors.New("signed delivery: NATS max_payload cannot hold a durable operation")
	}
	dispatch, err := r.deliveryDispatcher(r.lifetimeCtx, state, *options.Delivery)
	if err != nil {
		return err
	}
	cell, ok := contracts.CellIdTryCreate(r.topology.Cell)
	if !ok {
		return errors.New("signed command ingress cell is invalid")
	}
	aggregateValue := options.CommandAggregateID
	if strings.TrimSpace(aggregateValue) == "" {
		aggregateValue = "delivery"
	}
	aggregate, ok := contracts.AggregateIdTryCreate(aggregateValue)
	if !ok {
		return errors.New("signed command ingress aggregate is invalid")
	}
	generation, _ := protocol.DesiredGenerationTryCreate(1)
	epoch, _ := protocol.WriterEpochTryCreate(1)
	version, _ := protocol.ProtocolRevisionTryCreate(int64(protocol.ProtocolVersion.Current()))
	subject, err := r.topology.DirectDeliverySubject()
	if err != nil {
		return errors.New("signed command ingress subject is invalid")
	}
	replay, err := NewNatsCommandReplayStore(state.commandReplay)
	if err != nil {
		return err
	}
	ingress, err := NewNatsCommandIngress(NatsCommandIngressConfiguration{
		Connection: r.client, Subject: subject, Identity: options.CommandIdentity,
		Replay: replay, MultiInstance: true, ExpectedCell: cell,
		ExpectedAggregateID: aggregate, MinimumDesiredGeneration: generation,
		MinimumWriterEpoch: epoch, AcceptedProtocolVersions: []protocol.ProtocolRevision{version},
		AllowedClockSkew: 2 * time.Minute, MaximumValidityWindow: natsRuntimeCommandValidityWindow,
		PayloadDigestVerifier: sha256CommandPayloadDigestVerifier{}, Dispatch: dispatch,
	})
	if err != nil {
		return errors.New("signed command ingress could not be composed")
	}
	if err := ingress.Start(r.lifetimeCtx); err != nil {
		_ = ingress.Close()
		return err
	}
	r.commandIngress = ingress
	return nil
}

func natsRuntimeVerifyDurableProof(ctx context.Context, consumer jetstream.Consumer, topology *NatsTopology, jsClient *nats.Conn) error {
	if consumer == nil || jsClient == nil {
		return errors.New("NATS startup proof dependencies are required.")
	}
	proofCtx, cancel := context.WithTimeout(ctx, natsRuntimeProofTimeout)
	defer cancel()
	js, err := jetstream.New(jsClient)
	if err != nil {
		return err
	}
	identifierBytes := make([]byte, 16)
	if _, err := rand.Read(identifierBytes); err != nil {
		return err
	}
	identifier := hex.EncodeToString(identifierBytes)
	subject, err := topology.StartupSubject()
	if err != nil {
		return err
	}
	messageId, _ := protocol.MessageIdentityTokenTryCreate(identifier)
	correlationId := messageId
	targetCell := topology.Cell
	payload := natsRuntimeStartupProof{Nonce: identifier}
	body, err := protocol.MarshalMessagingEnvelope(&protocol.MessagingEnvelope{
		SchemaVersion: protocol.MessagingSchemaVersionCurrent,
		MessageId:     messageId,
		CorrelationId: &correlationId,
		Source: protocol.MessagingSource{
			Instance: topology.Instance,
			Session:  identifier,
			Cell:     topology.Cell,
			Cluster:  "orchestrator-control-" + topology.Cell,
		},
		Target: protocol.MessagingTargetScope{
			Namespace: natspolicy.NatsSubjectNamespaceRegionalControl,
			Subject:   subject,
			Cell:      &targetCell,
		},
		PayloadType: "runtime-startup-proof",
		ObservedAt:  time.Now().UTC(),
	}, payload)
	if err != nil {
		return err
	}
	message := &nats.Msg{Subject: subject, Data: body}
	if _, err := js.PublishMsg(proofCtx, message, jetstream.WithMsgID(identifier), jetstream.WithExpectStream("CELL_EVENTS")); err != nil {
		return err
	}
	received, err := consumer.Next(jetstream.FetchMaxWait(natsRuntimeProofTimeout))
	if err != nil {
		return err
	}
	if received == nil || received.Subject() != subject {
		return errors.New("Durable NATS startup event metadata was invalid.")
	}
	envelope, encodedPayload, err := protocol.UnmarshalMessagingEnvelope(
		received.Data(), subject, map[string]struct{}{"runtime-startup-proof": {}})
	if err != nil || envelope.MessageId.Value != identifier || envelope.CorrelationId == nil ||
		envelope.CorrelationId.Value != identifier || envelope.Source.Instance != topology.Instance ||
		envelope.Source.Cell != topology.Cell {
		return errors.New("Durable NATS startup event metadata was invalid.")
	}
	var receivedPayload natsRuntimeStartupProof
	if err := json.Unmarshal(encodedPayload, &receivedPayload); err != nil || receivedPayload != payload {
		return errors.New("Durable NATS startup event metadata was invalid.")
	}
	canonicalPayload, _ := json.Marshal(receivedPayload)
	if !bytes.Equal(canonicalPayload, encodedPayload) {
		return errors.New("Durable NATS startup event metadata was invalid.")
	}
	return received.DoubleAck(proofCtx)
}

type natsRuntimeStartupProof struct {
	Nonce string `json:"nonce"`
}

func (r *NatsRuntime) startService() error {
	if r == nil || r.client == nil || r.authority == nil || r.membership == nil || r.topology == nil {
		return errors.New("NATS runtime composition is incomplete.")
	}
	r.service = shared.NewNatsSvcServer(r.client, shared.NatsSvcConfig{
		Name: r.topology.ServiceName(), Version: "1.0.0", Description: "TerraScale regional control service",
		Metadata:   map[string]string{"cell": r.topology.Cell, "instance": r.topology.Instance},
		QueueGroup: r.topology.ServiceQueueGroup(),
	})
	add := func(name string, subject string, metadata map[string]string, handler func(context.Context, *nats.Msg) error) error {
		return r.service.AddEndpoint(shared.NatsSvcEndpointConfig{Name: name, Subject: subject, Metadata: metadata, Handler: handler})
	}
	replyEnvelope := func(subject, payloadType string, value any, message *nats.Msg) error {
		observedAt := time.Now().UTC()
		identity, messageId, err := NewNatsMessageIdentity()
		if err != nil {
			return err
		}
		cell := r.topology.Cell
		encoded, err := protocol.MarshalMessagingEnvelope(&protocol.MessagingEnvelope{
			SchemaVersion: protocol.MessagingSchemaVersionCurrent,
			MessageId:     messageId,
			Source: protocol.MessagingSource{
				Instance: r.topology.Instance,
				Session:  identity,
				Cell:     cell,
				Cluster:  "orchestrator-control-" + cell,
			},
			Target: protocol.MessagingTargetScope{
				Namespace: natspolicy.NatsSubjectNamespaceRegionalControl,
				Subject:   subject,
				Cell:      &cell,
			},
			PayloadType: payloadType,
			ObservedAt:  observedAt,
		}, value)
		if err != nil {
			return err
		}
		return message.Respond(encoded)
	}
	healthSubject, err := r.topology.HealthSubject()
	if err != nil {
		return err
	}
	instanceHealthSubject, err := r.topology.InstanceHealthSubject()
	if err != nil {
		return err
	}
	statusSubject, err := r.topology.StatusSubject()
	if err != nil {
		return err
	}
	membersSubject, err := r.topology.MembersSubject()
	if err != nil {
		return err
	}
	statsSubject, err := r.topology.StatsSubject()
	if err != nil {
		return err
	}
	healthHandler := func(subject string) func(context.Context, *nats.Msg) error {
		return func(_ context.Context, message *nats.Msg) error {
			value := "not-ready"
			if r.ready() {
				value = "ready"
			}
			return replyEnvelope(subject, "controller-health", struct {
				Status string `json:"status"`
			}{Status: value}, message)
		}
	}
	protocolVersion := fmt.Sprint(protocol.ProtocolVersion.Current())
	if err := add("health", healthSubject, map[string]string{"protocol": protocolVersion}, healthHandler(healthSubject)); err != nil {
		return err
	}
	if err := add("instance_health", instanceHealthSubject, map[string]string{"protocol": protocolVersion, "instance": r.topology.Instance}, healthHandler(instanceHealthSubject)); err != nil {
		return err
	}
	startedAt := time.Now().UTC()
	capabilities := []string{"authority", "authority-election", "delivery", "messaging", "observability", "operator-read", "provider-ownership", "reconciliation", "regional-membership", "runtime", "scheduler", "security", "service-discovery", "storage", "terrabase", "nats-nkey-authenticated", "nats-mtls"}
	sort.Strings(capabilities)
	if err := add("status", statusSubject, map[string]string{"protocol": protocolVersion, "readOnly": "true"}, func(_ context.Context, message *nats.Msg) error {
		snapshot := r.authority.Snapshot()
		return replyEnvelope(statusSubject, "controller-status", &RegionalControllerStatus{SchemaVersion: protocol.ProtocolVersion.Current(), Cell: r.topology.Cell, Instance: r.topology.Instance, ControlReplicas: r.topology.Replicas, Ready: r.ready(), StartedAt: startedAt, ObservedAt: time.Now().UTC(), Build: "unknown", Capabilities: capabilities, AuthorityState: snapshot.State, IsAuthorityLeader: snapshot.IsLeader, AuthorityEpoch: snapshot.Epoch, AuthorityRevision: snapshot.KvRevision, AuthorityLeaseExpiresAt: snapshot.LeaseExpiresAt}, message)
	}); err != nil {
		return err
	}
	if err := add("members", membersSubject, map[string]string{"protocol": protocolVersion, "readOnly": "true", "source": r.topology.Runtime().Bucket}, func(_ context.Context, message *nats.Msg) error {
		return replyEnvelope(membersSubject, "controller-membership", r.membership.Snapshot(), message)
	}); err != nil {
		return err
	}
	if err := add("stats", statsSubject, map[string]string{"protocol": protocolVersion, "readOnly": "true", "schema": "aggregated"}, func(_ context.Context, message *nats.Msg) error {
		document, err := NatsServiceStatsDocumentCreate(r.topology.Cell, "unknown", protocol.ProtocolVersion.Current(), r.ready(), time.Now().UTC(), r.stats.Snapshot())
		if err != nil {
			return err
		}
		return replyEnvelope(statsSubject, "controller-stats", document, message)
	}); err != nil {
		return err
	}
	if err := r.service.Start(r.lifetimeCtx); err != nil {
		return err
	}
	infoSubject := "$SRV.INFO." + r.topology.ServiceName()
	info, err := r.client.Subscribe(infoSubject, func(message *nats.Msg) { _ = message.Respond(r.service.DiscoveryDocument()) })
	if err != nil {
		r.service.Stop()
		return err
	}
	r.serviceInfo = info
	return r.client.Flush()
}

func (r *NatsRuntime) ready() bool {
	return r != nil && r.authority != nil && r.membership != nil &&
		r.authority.Snapshot().Ready() && r.membership.LastFailure() == nil
}

// Completion closes when either long-running controller component exits.
func (r *NatsRuntime) Completion() <-chan struct{} {
	if r == nil {
		return nil
	}
	return r.completion
}
func (r *NatsRuntime) complete() {
	if r == nil {
		return
	}
	r.completionOnce.Do(func() { close(r.completion) })
}
func (r *NatsRuntime) AuthoritySnapshot() RegionalAuthoritySnapshot {
	if r == nil || r.authority == nil {
		return RegionalAuthoritySnapshot{}
	}
	return r.authority.Snapshot()
}
func (r *NatsRuntime) MembershipSnapshot() RegionalRuntimeMembershipSnapshot {
	if r == nil || r.membership == nil {
		return RegionalRuntimeMembershipSnapshot{}
	}
	return r.membership.Snapshot()
}
func (r *NatsRuntime) MembershipHealth() RegionalRuntimeMembershipHealth {
	return r.MembershipSnapshot().Health
}
func (r *NatsRuntime) Cell() string {
	if r == nil || r.topology == nil {
		return ""
	}
	return r.topology.Cell
}

// Close deterministically tears down every started component in reverse order.
func (r *NatsRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		if r.completion == nil {
			r.completion = make(chan struct{})
		}
		atomic.StoreInt32(&r.closed, 1)
		if r.cancel != nil {
			r.cancel()
		}
		if r.commandIngress != nil {
			if err := r.commandIngress.Close(); err != nil {
				r.closeErr = err
			}
		}
		if r.serviceInfo != nil {
			_ = r.serviceInfo.Drain()
		}
		if r.service != nil {
			r.service.Stop()
		}
		if r.membership != nil {
			if err := r.membership.Dispose(); err != nil && r.closeErr == nil {
				r.closeErr = err
			}
		}
		if r.membershipIdentity != nil {
			r.membershipIdentity.Dispose()
		}
		if r.authority != nil {
			r.authority.Dispose()
		}
		if r.client != nil {
			r.client.Close()
		}
		r.complete()
	})
	return r.closeErr
}

// Dispose is the migration-compatible deterministic close spelling.
func (r *NatsRuntime) Dispose() error { return r.Close() }
