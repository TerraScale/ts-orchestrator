package provider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

type createNodeHardeningFixture struct {
	request          CreateNodeProviderRequest
	keys             *ReceiptKeyRing
	proofSigner      *CreateNodeProviderProofSigner
	receiptSigner    *CreateNodeHandoffReceiptSigner
	invocationSigner *CreateNodeAuthoritativeInvocationCapabilitySigner
	launchResolver   OciNodeLaunchResolver
	now              time.Time
}

func newCreateNodeHardeningFixture(t *testing.T) createNodeHardeningFixture {
	t.Helper()
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := NewReceiptKeyRing(map[string][]byte{"create-node-authority": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := []byte("#cloud-config\nruncmd: []\n")
	digest := sha256.Sum256(bootstrap)
	parameters := CreateNodeProviderParameters{
		TemplateId: ProviderTemplateId{Value: "template-1"}, PlacementId: ProviderPlacementId{Value: "placement-1"},
		BootstrapEnvelopeDigest: ProviderBootstrapEnvelopeDigest{Sha256: hex.EncodeToString(digest[:])},
	}
	operationContext, err := NewProviderOperationContext(
		ProviderOperationId{Value: "operation-1"}, ProviderCellId{Value: "gru"}, ProviderCompartmentId{Value: "ocid1.compartment.oc1.x"},
		ProviderEpoch{Value: 1}, ResourceNode, ActionCreateNode, IdempotentProviderCreate{Key: ProviderCreateKey{Value: "create-1"}},
		ProviderGeneration{Value: 7}, ObservedAbsent, TerminalPresent, nil,
		DeadlineEvidence{Status: DeadlineValid, EvidenceGeneration: ProviderGeneration{Value: 7}}, ProviderIdempotencyKey{Value: "idempotency-1"}, nil, parameters,
	)
	if err != nil {
		t.Fatal(err)
	}
	binding := CreateNodeReceiptBinding{
		OperationId: "operation-1", TenantId: "tenant-1", NodeRequestId: "node-request-1", IdempotencyKey: "idempotency-1",
		CreateKey: "create-1", CellId: "gru", CompartmentId: "ocid1.compartment.oc1.x", TemplateId: "template-1", PlacementId: "placement-1",
		BootstrapEnvelopeDigest: parameters.BootstrapEnvelopeDigest.Sha256, AuthorizationDigest: "authorization-digest",
		ProviderContextFingerprint: operationContext.Fingerprint(), Generation: 7, Epoch: 1, AuthorizationSequence: 1,
	}
	receiptSigner, err := NewCreateNodeHandoffReceiptSigner("create-node-authority", key)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := receiptSigner.Sign(binding, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	invocationSigner, err := NewInvocationCapabilitySigner("create-node-authority", key)
	if err != nil {
		t.Fatal(err)
	}
	capability, err := invocationSigner.Sign(CreateNodeAuthoritativeInvocationCapability{
		OperationId: binding.OperationId, BindingDigest: binding.Digest(), JournalVersion: 1,
		LeaseOwner: "controller-1", LeaseToken: "lease-1", Nonce: "nonce-1",
		LeaseExpiresAt: now.Add(5 * time.Minute), IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	recoverySigner, err := NewCreateNodeRecoveryLookupSigner("create-node-authority", key)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := recoverySigner.Sign(binding, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	proofSigner, err := NewCreateNodeProviderProofSigner("create-node-authority", key)
	if err != nil {
		t.Fatal(err)
	}
	resolver := OciNodeLaunchResolverFunc(func(context.Context, ProviderTemplateId, ProviderPlacementId, ProviderBootstrapEnvelopeDigest) (OciNodeLaunchSpec, error) {
		return OciNodeLaunchSpec{
			CompartmentId: "ocid1.compartment.oc1.x", AvailabilityDomain: "AD-1", FaultDomain: "FD-1",
			SubnetId: "ocid1.subnet.oc1.x", ImageId: "ocid1.image.oc1.x", Shape: "VM.Standard.A1.Flex",
			NetworkSecurityGroupIds: []string{"ocid1.networksecuritygroup.oc1.x"}, Ocpus: 4, MemoryGB: 24,
			BootstrapBase64: base64.StdEncoding.EncodeToString(bootstrap),
		}, nil
	})
	return createNodeHardeningFixture{
		request: CreateNodeProviderRequest{
			Context: operationContext, Parameters: parameters, Binding: binding, Receipt: receipt,
			RecoveryAuthority: recovery, InvocationCapability: &capability,
		},
		keys: keys, proofSigner: proofSigner, receiptSigner: receiptSigner, invocationSigner: invocationSigner,
		launchResolver: resolver, now: now,
	}
}

func newCreateNodeTestJournal(t *testing.T) *CASCreateNodeJournal {
	t.Helper()
	journal, err := NewCASCreateNodeJournal(newTestOwnershipCAS())
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func createNodeProvider(fixture createNodeHardeningFixture, transport *OCIHTTPTransport, journal CreateNodeJournal, ownership DurableOwnershipEvidence, now func() time.Time) *OciCreateNodeProvider {
	return &OciCreateNodeProvider{
		Enabled: true, OCI: transport, ProofSigner: fixture.proofSigner,
		Keys: fixture.keys, RecoveryKeys: fixture.keys, InvocationKeys: fixture.keys,
		Journal: journal, Clock: now, LaunchResolver: fixture.launchResolver, Ownership: ownership,
	}
}

func prepareCreateNodeConsumption(t *testing.T, fixture createNodeHardeningFixture, transport *OCIHTTPTransport, at time.Time) (ociNodeLaunchRequest, CreateNodeInvocationConsumption) {
	t.Helper()
	client := &OCIComputeNodeClient{OCI: transport, LaunchResolver: fixture.launchResolver}
	launch, err := client.prepareNodeLaunch(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	return launch, newCreateNodeInvocationConsumption(fixture.request, *fixture.request.InvocationCapability, launch, at)
}

func persistCreateNodeConsumption(t *testing.T, journal CreateNodeJournal, fixture createNodeHardeningFixture, consumption CreateNodeInvocationConsumption) {
	t.Helper()
	if err := journal.ConsumeInvocationCapability(context.Background(), *fixture.request.InvocationCapability, fixture.request.Binding, consumption); err != nil {
		t.Fatal(err)
	}
}

type staticCreateNodeJournal struct {
	consumption CreateNodeInvocationConsumption
	found       bool
	lookupErr   error
	consumeErr  error
}

func (j *staticCreateNodeJournal) AuthoritativeDurable() bool { return j != nil }
func (j *staticCreateNodeJournal) ConsumeInvocationCapability(context.Context, CreateNodeAuthoritativeInvocationCapability, CreateNodeReceiptBinding, CreateNodeInvocationConsumption) error {
	return j.consumeErr
}
func (j *staticCreateNodeJournal) InvocationCapabilityConsumption(context.Context, CreateNodeAuthoritativeInvocationCapability, CreateNodeReceiptBinding) (CreateNodeInvocationConsumption, bool, error) {
	return j.consumption, j.found, j.lookupErr
}

type recordFailingCreateNodeOwnership struct {
	DurableOwnershipEvidence
	err error
}

func (o *recordFailingCreateNodeOwnership) Record(context.Context, ProviderOwnershipRecord) error {
	return o.err
}

func TestCASCreateNodeJournalPersistsExactOneShotRequest(t *testing.T) {
	fixture := newCreateNodeHardeningFixture(t)
	transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
		return nil, errors.New("journal test must not send OCI requests")
	})
	launch, consumption := prepareCreateNodeConsumption(t, fixture, transport, fixture.now)
	journal := newCreateNodeTestJournal(t)
	persistCreateNodeConsumption(t, journal, fixture, consumption)
	launch.request.Body[0] ^= 0xff

	stored, found, err := journal.InvocationCapabilityConsumption(context.Background(), *fixture.request.InvocationCapability, fixture.request.Binding)
	if err != nil || !found || !reflect.DeepEqual(stored, consumption) {
		t.Fatalf("stored consumption = %+v, found=%v, err=%v", stored, found, err)
	}
	if stored.ProviderRequest.Digest != stored.ProviderRequest.calculatedDigest() ||
		stored.ProviderRequest.Authority != transport.Config.Endpoint.Host || stored.ProviderRequest.Service != OCIServiceCore ||
		stored.ProviderRequest.Region != transport.Config.Region || stored.ProviderRequest.RetryToken != fixture.request.Binding.IdempotencyKey ||
		stored.OperationId != fixture.request.Binding.OperationId || stored.CreateKey != fixture.request.Binding.CreateKey {
		t.Fatalf("stored request proof is incomplete: %+v", stored)
	}
	if err := journal.ConsumeInvocationCapability(context.Background(), *fixture.request.InvocationCapability, fixture.request.Binding, consumption); err == nil {
		t.Fatal("consumed invocation capability was accepted twice")
	}
}

func TestOCINodeCreateLostBeforeSendObservesThenReplaysExactRequest(t *testing.T) {
	fixture := newCreateNodeHardeningFixture(t)
	instanceID := "ocid1.instance.oc1.created"
	methods := make([]string, 0, 3)
	var bodies [][]byte
	var tokens []string
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		methods = append(methods, request.Method)
		switch request.Method {
		case http.MethodPost:
			body, err := io.ReadAll(request.Body)
			if err != nil {
				return nil, err
			}
			bodies = append(bodies, body)
			tokens = append(tokens, request.Header.Get("opc-retry-token"))
			if len(bodies) == 1 {
				return nil, io.ErrUnexpectedEOF
			}
			return testHTTPResponse(http.StatusOK, `{"id":"`+instanceID+`","compartmentId":"ocid1.compartment.oc1.x"}`, http.Header{"Opc-Work-Request-Id": {"work-created"}}), nil
		case http.MethodGet:
			return testHTTPResponse(http.StatusOK, `[]`, nil), nil
		default:
			return nil, errors.New("unexpected OCI method")
		}
	})
	transport.Config.MaxRetries = 4
	transport.retryDelay = func(context.Context, int) error { return nil }
	journal := newCreateNodeTestJournal(t)
	ownership := testOwnership(t)
	provider := createNodeProvider(fixture, transport, journal, ownership, func() time.Time { return fixture.now })
	response, err := provider.CreateNode(context.Background(), fixture.request)
	if err != nil || response.NodeId.Value != instanceID || response.WorkRequestId.Value != "work-created" {
		t.Fatalf("lost-before-send create = %+v, %v", response, err)
	}
	if !reflect.DeepEqual(methods, []string{http.MethodPost, http.MethodGet, http.MethodPost}) || len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) || len(tokens) != 2 || tokens[0] != fixture.request.Binding.IdempotencyKey || tokens[1] != tokens[0] {
		t.Fatalf("exact replay methods=%v tokens=%v bodiesEqual=%v", methods, tokens, len(bodies) == 2 && bytes.Equal(bodies[0], bodies[1]))
	}
	record, found, lookupErr := ownership.Lookup(context.Background(), response.NodeId)
	if lookupErr != nil || !found || record.ResourceId != response.NodeId || record.Generation.Value != fixture.request.Binding.Generation {
		t.Fatalf("created ownership = %+v, found=%v, err=%v", record, found, lookupErr)
	}
}

func TestOCINodeCreateLostAfterAcceptNeverAdoptsRetaggedOwnedCollision(t *testing.T) {
	fixture := newCreateNodeHardeningFixture(t)
	realID := "ocid1.instance.oc1.real"
	attackID := "ocid1.instance.oc1.retagged"
	methods := make([]string, 0, 3)
	posts := 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		methods = append(methods, request.Method)
		switch request.Method {
		case http.MethodPost:
			posts++
			if posts == 1 {
				return nil, io.ErrUnexpectedEOF
			}
			return testHTTPResponse(http.StatusOK, `{"id":"`+realID+`","compartmentId":"ocid1.compartment.oc1.x"}`, http.Header{"Opc-Work-Request-Id": {"work-real"}}), nil
		case http.MethodGet:
			return testHTTPResponse(http.StatusOK, `[{"id":"`+attackID+`","compartmentId":"ocid1.compartment.oc1.x","freeformTags":{"terrascale-create-key":"create-1","terrascale-operation":"operation-1"}}]`, nil), nil
		default:
			return nil, errors.New("unexpected OCI method")
		}
	})
	ownership := testOwnership(t)
	wantAttack := ProviderOwnershipRecord{
		ResourceId: ProviderResourceId{Value: attackID}, CellId: fixture.request.Context.CellId,
		CompartmentId: fixture.request.Context.CompartmentId, Generation: fixture.request.Context.ExpectedGeneration,
	}
	if err := ownership.Record(context.Background(), wantAttack); err != nil {
		t.Fatal(err)
	}
	provider := createNodeProvider(fixture, transport, newCreateNodeTestJournal(t), ownership, func() time.Time { return fixture.now })
	response, err := provider.CreateNode(context.Background(), fixture.request)
	if err != nil || response.NodeId.Value != realID || posts != 2 || !reflect.DeepEqual(methods, []string{http.MethodPost, http.MethodGet, http.MethodPost}) {
		t.Fatalf("lost-after-accept create=%+v methods=%v posts=%d err=%v", response, methods, posts, err)
	}
	attack, found, err := ownership.Lookup(context.Background(), wantAttack.ResourceId)
	if err != nil || !found || attack != wantAttack {
		t.Fatalf("retagged ownership changed: %+v, found=%v, err=%v", attack, found, err)
	}
}

func TestOCINodeLookupOnlyAuthorityObservesButNeverPostsOrAdoptsTags(t *testing.T) {
	fixture := newCreateNodeHardeningFixture(t)
	fixture.request.InvocationCapability = nil
	attackID := "ocid1.instance.oc1.lookupcollision"
	gets, posts := 0, 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			gets++
			return testHTTPResponse(http.StatusOK, `[{"id":"`+attackID+`","compartmentId":"ocid1.compartment.oc1.x","freeformTags":{"terrascale-create-key":"create-1","terrascale-operation":"operation-1"}}]`, nil), nil
		}
		posts++
		return nil, errors.New("lookup authority attempted a mutation")
	})
	ownership := testOwnership(t)
	want := ProviderOwnershipRecord{
		ResourceId: ProviderResourceId{Value: attackID}, CellId: fixture.request.Context.CellId,
		CompartmentId: fixture.request.Context.CompartmentId, Generation: fixture.request.Context.ExpectedGeneration,
	}
	if err := ownership.Record(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	provider := createNodeProvider(fixture, transport, newCreateNodeTestJournal(t), ownership, func() time.Time { return fixture.now })
	reconciliation, err := provider.ReconcileCreateNode(context.Background(), fixture.request)
	if err != nil || reconciliation.Status != CreateNodeUnknown || gets != 1 || posts != 0 {
		t.Fatalf("lookup reconciliation=%+v gets=%d posts=%d err=%v", reconciliation, gets, posts, err)
	}
	got, found, err := ownership.Lookup(context.Background(), want.ResourceId)
	if err != nil || !found || got != want {
		t.Fatalf("lookup-only ownership changed: %+v, found=%v, err=%v", got, found, err)
	}
}

func TestOCINodeLookupOnlyObservationRejectsPaginationCycles(t *testing.T) {
	fixture := newCreateNodeHardeningFixture(t)
	fixture.request.InvocationCapability = nil
	gets, posts := 0, 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet {
			posts++
			return nil, errors.New("lookup authority attempted a mutation")
		}
		gets++
		if (gets == 1 && request.URL.Query().Get("page") != "") || (gets == 2 && request.URL.Query().Get("page") != "cursor-1") {
			return nil, errors.New("observation sent the wrong page token")
		}
		return testHTTPResponse(http.StatusOK, `[]`, http.Header{"Opc-Next-Page": {"cursor-1"}}), nil
	})
	provider := createNodeProvider(fixture, transport, newCreateNodeTestJournal(t), testOwnership(t), func() time.Time { return fixture.now })
	_, err := provider.ReconcileCreateNode(context.Background(), fixture.request)
	if !errors.As(err, new(*InvalidDataError)) || gets != 2 || posts != 0 {
		t.Fatalf("pagination cycle gets=%d posts=%d err=%v", gets, posts, err)
	}
}

func TestOCINodeRecoveryRejectsEndpointDriftBeforeReplay(t *testing.T) {
	fixture := newCreateNodeHardeningFixture(t)
	original := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
		return nil, errors.New("original transport is preparation-only")
	})
	_, consumption := prepareCreateNodeConsumption(t, fixture, original, fixture.now.Add(-time.Second))
	journal := newCreateNodeTestJournal(t)
	persistCreateNodeConsumption(t, journal, fixture, consumption)

	config, err := NewOCITransportConfig("sfo", "https://iaas.sfo.oraclecloud.com")
	if err != nil {
		t.Fatal(err)
	}
	gets, posts := 0, 0
	restarted, err := NewOCIHTTPTransport(config, &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			gets++
			return testHTTPResponse(http.StatusOK, `[]`, nil), nil
		}
		posts++
		return nil, errors.New("drifted authority received a replay")
	})}, nil)
	if err != nil {
		t.Fatal(err)
	}
	resolverCalls := 0
	fixture.launchResolver = OciNodeLaunchResolverFunc(func(context.Context, ProviderTemplateId, ProviderPlacementId, ProviderBootstrapEnvelopeDigest) (OciNodeLaunchSpec, error) {
		resolverCalls++
		return OciNodeLaunchSpec{}, errors.New("drifted resolver must not run during recovery")
	})
	provider := createNodeProvider(fixture, restarted, journal, testOwnership(t), func() time.Time { return fixture.now })
	reconciliation, err := provider.ReconcileCreateNode(context.Background(), fixture.request)
	if err != nil || reconciliation.Status != CreateNodeUnknown || gets != 1 || posts != 0 || resolverCalls != 0 {
		t.Fatalf("drift recovery=%+v gets=%d posts=%d resolverCalls=%d err=%v", reconciliation, gets, posts, resolverCalls, err)
	}
}

func TestOCINodeRecoveryReplaysStoredBytesWithoutRestartResolver(t *testing.T) {
	fixture := newCreateNodeHardeningFixture(t)
	transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
		return nil, errors.New("placeholder")
	})
	_, consumption := prepareCreateNodeConsumption(t, fixture, transport, fixture.now.Add(-time.Second))
	journal := newCreateNodeTestJournal(t)
	persistCreateNodeConsumption(t, journal, fixture, consumption)

	resolverCalls := 0
	fixture.launchResolver = OciNodeLaunchResolverFunc(func(context.Context, ProviderTemplateId, ProviderPlacementId, ProviderBootstrapEnvelopeDigest) (OciNodeLaunchSpec, error) {
		resolverCalls++
		return OciNodeLaunchSpec{}, errors.New("restart resolver must not rebuild a consumed request")
	})
	var posted []byte
	transport.Client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			return testHTTPResponse(http.StatusOK, `[]`, nil), nil
		}
		posted, _ = io.ReadAll(request.Body)
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.instance.oc1.restarted","compartmentId":"ocid1.compartment.oc1.x"}`, http.Header{"Opc-Work-Request-Id": {"work-restarted"}}), nil
	})}
	provider := createNodeProvider(fixture, transport, journal, testOwnership(t), func() time.Time { return fixture.now })
	reconciliation, err := provider.ReconcileCreateNode(context.Background(), fixture.request)
	if err != nil || reconciliation.Status != CreateNodeFound || reconciliation.Response == nil || reconciliation.Response.NodeId.Value != "ocid1.instance.oc1.restarted" || resolverCalls != 0 || !bytes.Equal(posted, consumption.ProviderRequest.Body) {
		t.Fatalf("restart recovery=%+v resolverCalls=%d exactBody=%v err=%v", reconciliation, resolverCalls, bytes.Equal(posted, consumption.ProviderRequest.Body), err)
	}
	if reconciliation.Proof == nil || !VerifyCreateNodeProviderProof(*reconciliation.Proof, fixture.keys, fixture.request.Binding) {
		t.Fatal("restart recovery did not return an exact signed provider proof")
	}
}

func TestOCINodeRecoveryRejectsInvalidDurableTimeOrder(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(t *testing.T, fixture *createNodeHardeningFixture, consumption *CreateNodeInvocationConsumption)
		recoverAt func(createNodeHardeningFixture) time.Time
	}{
		{
			name: "before capability issuance",
			mutate: func(_ *testing.T, fixture *createNodeHardeningFixture, consumption *CreateNodeInvocationConsumption) {
				consumption.ConsumedAt = fixture.request.InvocationCapability.IssuedAt.Add(-time.Nanosecond)
				consumption.SubmissionCommittedAt = consumption.ConsumedAt
			},
			recoverAt: func(f createNodeHardeningFixture) time.Time { return f.now },
		},
		{
			name: "before receipt issuance",
			mutate: func(t *testing.T, fixture *createNodeHardeningFixture, consumption *CreateNodeInvocationConsumption) {
				issued := fixture.now.Add(-30 * time.Second)
				receipt, err := fixture.receiptSigner.Sign(fixture.request.Binding, issued, fixture.now.Add(time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				fixture.request.Receipt = receipt
				consumption.ReceiptDigest = handoffReceiptDigest(receipt)
				consumption.ReceiptIssuedAt = issued
				consumption.ReceiptExpiresAt = receipt.ExpiresAt
				consumption.ConsumedAt = issued.Add(-time.Nanosecond)
				consumption.SubmissionCommittedAt = consumption.ConsumedAt
			},
			recoverAt: func(f createNodeHardeningFixture) time.Time { return f.now },
		},
		{
			name: "at capability expiry",
			mutate: func(_ *testing.T, fixture *createNodeHardeningFixture, consumption *CreateNodeInvocationConsumption) {
				consumption.ConsumedAt = fixture.request.InvocationCapability.ExpiresAt
				consumption.SubmissionCommittedAt = consumption.ConsumedAt
			},
			recoverAt: func(f createNodeHardeningFixture) time.Time { return f.request.InvocationCapability.ExpiresAt },
		},
		{
			name: "after lease expiry",
			mutate: func(_ *testing.T, fixture *createNodeHardeningFixture, consumption *CreateNodeInvocationConsumption) {
				consumption.ConsumedAt = fixture.request.InvocationCapability.LeaseExpiresAt.Add(time.Nanosecond)
				consumption.SubmissionCommittedAt = consumption.ConsumedAt
			},
			recoverAt: func(f createNodeHardeningFixture) time.Time {
				return f.request.InvocationCapability.LeaseExpiresAt.Add(time.Nanosecond)
			},
		},
		{
			name: "submission before consumption",
			mutate: func(_ *testing.T, _ *createNodeHardeningFixture, consumption *CreateNodeInvocationConsumption) {
				consumption.SubmissionCommittedAt = consumption.ConsumedAt.Add(-time.Nanosecond)
			},
			recoverAt: func(f createNodeHardeningFixture) time.Time { return f.now },
		},
		{
			name: "submission in the future",
			mutate: func(_ *testing.T, fixture *createNodeHardeningFixture, consumption *CreateNodeInvocationConsumption) {
				consumption.ConsumedAt = fixture.now.Add(time.Nanosecond)
				consumption.SubmissionCommittedAt = consumption.ConsumedAt
			},
			recoverAt: func(f createNodeHardeningFixture) time.Time { return f.now },
		},
		{
			name: "retry token window expired",
			mutate: func(_ *testing.T, fixture *createNodeHardeningFixture, consumption *CreateNodeInvocationConsumption) {
				at := fixture.now.Add(-ociRetryTokenValidity)
				consumption.ConsumedAt = at
				consumption.SubmissionCommittedAt = at
			},
			recoverAt: func(f createNodeHardeningFixture) time.Time { return f.now },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCreateNodeHardeningFixture(t)
			posts := 0
			transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodGet {
					return testHTTPResponse(http.StatusOK, `[]`, nil), nil
				}
				posts++
				return nil, errors.New("invalid temporal proof was replayed")
			})
			_, consumption := prepareCreateNodeConsumption(t, fixture, transport, fixture.now.Add(-time.Second))
			test.mutate(t, &fixture, &consumption)
			journal := &staticCreateNodeJournal{consumption: consumption, found: true}
			provider := createNodeProvider(fixture, transport, journal, testOwnership(t), func() time.Time { return test.recoverAt(fixture) })
			reconciliation, err := provider.ReconcileCreateNode(context.Background(), fixture.request)
			if err != nil || reconciliation.Status != CreateNodeUnknown || posts != 0 {
				t.Fatalf("temporal recovery=%+v posts=%d err=%v", reconciliation, posts, err)
			}
		})
	}
}

func TestOCINodeRecoveryJournalLookupFailureNeverPosts(t *testing.T) {
	fixture := newCreateNodeHardeningFixture(t)
	lookupErr := errors.New("durable journal lookup failed")
	posts := 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			return testHTTPResponse(http.StatusOK, `[]`, nil), nil
		}
		posts++
		return nil, errors.New("journal failure attempted a POST")
	})
	provider := createNodeProvider(fixture, transport, &staticCreateNodeJournal{lookupErr: lookupErr}, testOwnership(t), func() time.Time { return fixture.now })
	reconciliation, err := provider.ReconcileCreateNode(context.Background(), fixture.request)
	if !errors.Is(err, lookupErr) || reconciliation != (CreateNodeReconciliation{}) || posts != 0 {
		t.Fatalf("journal failure reconciliation=%+v posts=%d err=%v", reconciliation, posts, err)
	}
}

func TestOCINodeCreateJournalAndOwnershipFailuresNeverReturnSuccess(t *testing.T) {
	t.Run("journal consumption", func(t *testing.T) {
		fixture := newCreateNodeHardeningFixture(t)
		posts := 0
		transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
			posts++
			return nil, errors.New("journal failure attempted a POST")
		})
		provider := createNodeProvider(fixture, transport, &staticCreateNodeJournal{consumeErr: errors.New("consume failed")}, testOwnership(t), func() time.Time { return fixture.now })
		response, err := provider.CreateNode(context.Background(), fixture.request)
		if err == nil || response != (CreateNodeProviderResponse{}) || posts != 0 {
			t.Fatalf("journal failure response=%+v posts=%d err=%v", response, posts, err)
		}
	})

	t.Run("ownership record", func(t *testing.T) {
		fixture := newCreateNodeHardeningFixture(t)
		posts := 0
		transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
			posts++
			return testHTTPResponse(http.StatusOK, `{"id":"ocid1.instance.oc1.unrecorded","compartmentId":"ocid1.compartment.oc1.x"}`, http.Header{"Opc-Work-Request-Id": {"work-unrecorded"}}), nil
		})
		ownership := &recordFailingCreateNodeOwnership{DurableOwnershipEvidence: testOwnership(t), err: errors.New("ownership write failed")}
		provider := createNodeProvider(fixture, transport, newCreateNodeTestJournal(t), ownership, func() time.Time { return fixture.now })
		response, err := provider.CreateNode(context.Background(), fixture.request)
		if response != (CreateNodeProviderResponse{}) || !errors.As(err, new(*ProviderOutcomeUnknownError)) || posts != 1 {
			t.Fatalf("ownership failure response=%+v posts=%d err=%v", response, posts, err)
		}
	})
}

func TestOCINodeCreateRetryClassificationIsTerminalOrBounded(t *testing.T) {
	t.Run("501 terminal", func(t *testing.T) {
		fixture := newCreateNodeHardeningFixture(t)
		posts, gets := 0, 0
		transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodGet {
				gets++
			}
			posts++
			return testHTTPResponse(http.StatusNotImplemented, `{"code":"NotImplemented"}`, nil), nil
		})
		transport.Config.MaxRetries = 5
		transport.retryDelay = func(context.Context, int) error { return nil }
		provider := createNodeProvider(fixture, transport, newCreateNodeTestJournal(t), testOwnership(t), func() time.Time { return fixture.now })
		_, err := provider.CreateNode(context.Background(), fixture.request)
		if err == nil || errors.As(err, new(*ProviderOutcomeUnknownError)) || posts != 1 || gets != 0 {
			t.Fatalf("501 classification posts=%d gets=%d err=%v", posts, gets, err)
		}
	})

	t.Run("retryable response exhaustion", func(t *testing.T) {
		fixture := newCreateNodeHardeningFixture(t)
		posts, gets := 0, 0
		transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodGet {
				gets++
			} else {
				posts++
			}
			return testHTTPResponse(http.StatusServiceUnavailable, `{"code":"ServiceUnavailable"}`, nil), nil
		})
		transport.Config.MaxRetries = 2
		transport.retryDelay = func(context.Context, int) error { return nil }
		provider := createNodeProvider(fixture, transport, newCreateNodeTestJournal(t), testOwnership(t), func() time.Time { return fixture.now })
		_, err := provider.CreateNode(context.Background(), fixture.request)
		if !errors.As(err, new(*ProviderOutcomeUnknownError)) || !errors.As(err, new(*ociResponseRetriesExhaustedError)) || posts != transport.Config.MaxRetries+1 || gets != 0 {
			t.Fatalf("retry exhaustion posts=%d gets=%d err=%v", posts, gets, err)
		}
	})
}

func TestOCINodeCreateDoesNotFollowCrossAuthorityRedirect(t *testing.T) {
	fixture := newCreateNodeHardeningFixture(t)
	targetCalls := 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.URL.Host != "iaas.sa-saopaulo-1.oraclecloud.com" {
			targetCalls++
		}
		return testHTTPResponse(http.StatusTemporaryRedirect, "", http.Header{"Location": {"https://attacker.invalid/capture"}}), nil
	})
	provider := createNodeProvider(fixture, transport, newCreateNodeTestJournal(t), testOwnership(t), func() time.Time { return fixture.now })
	_, err := provider.CreateNode(context.Background(), fixture.request)
	if err == nil || targetCalls != 0 {
		t.Fatalf("redirect error=%v targetCalls=%d", err, targetCalls)
	}
}

func TestCreateNodeRequestProofBindsBodyAndAllProviderAuthorityFields(t *testing.T) {
	fixture := newCreateNodeHardeningFixture(t)
	transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
		return nil, errors.New("proof test must not send")
	})
	launch, _ := prepareCreateNodeConsumption(t, fixture, transport, fixture.now)
	proof := launch.request
	mutations := []func(*CreateNodeProviderRequestProof){
		func(p *CreateNodeProviderRequestProof) { p.Authority = "iaas.sfo.oraclecloud.com" },
		func(p *CreateNodeProviderRequestProof) { p.Service = OCIServiceIdentity },
		func(p *CreateNodeProviderRequestProof) { p.Region = "sfo" },
		func(p *CreateNodeProviderRequestProof) { p.Method = http.MethodPut },
		func(p *CreateNodeProviderRequestProof) { p.Path = "/20160918/instances/other" },
		func(p *CreateNodeProviderRequestProof) { p.CompartmentId = "ocid1.compartment.oc1.other" },
		func(p *CreateNodeProviderRequestProof) { p.RetryToken = "different" },
		func(p *CreateNodeProviderRequestProof) { p.BindingDigest = "different" },
		func(p *CreateNodeProviderRequestProof) { p.OperationId = "different" },
		func(p *CreateNodeProviderRequestProof) { p.CreateKey = "different" },
		func(p *CreateNodeProviderRequestProof) { p.CellId = "sfo" },
		func(p *CreateNodeProviderRequestProof) { p.Generation++ },
		func(p *CreateNodeProviderRequestProof) {
			p.Body = []byte(strings.ReplaceAll(string(p.Body), "VM.Standard.A1.Flex", "VM.Standard.E5.Flex"))
		},
	}
	for index, mutate := range mutations {
		changed := proof.clone()
		mutate(&changed)
		if changed.calculatedDigest() == proof.Digest {
			t.Fatalf("provider proof mutation %d did not change digest", index)
		}
	}
}
