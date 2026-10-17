//go:build linux

package app

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/common"
)

type rootWorkloadCredentials struct {
	rootsecret.MaterialService
	admission *rootMaterialAdmission
}

func newRootWorkloadCredentials(source *managedRuntimeHost, factory *ociclient.Factory) (rootoci.WorkloadCredentials, error) {
	admission, err := newRootMaterialAdmission(source, factory)
	if err != nil {
		return nil, err
	}
	return &rootWorkloadCredentials{MaterialService: rootsecret.MaterialService{AdmitContainer: admission.container, AdmitGeneration: admission.generation}, admission: admission}, nil
}

// This seal stays entirely within root. Native release identity never becomes a
// synthetic Swarm task or a caller-selected Vault reference.
type rootNativeCanaryAdmission struct {
	original        context.Context
	config          containerMaterialConfig
	history         *nativeHistory
	session         *host.NativeCanarySession
	lease           *authority.LeaseAdmission
	intent          delivery.Intent
	request         rootoci.NativeCanaryRequest
	spec            jetstream.KeyValueEntry
	rootChain       jetstream.KeyValueEntry
	rootHead        string
	historyRevision uint64
	markRevision    uint64
	mark            []byte
	desired         []byte
	reference       vaultsecret.Ref
	deadline        time.Time
}

func (service *rootWorkloadCredentials) MaterializeNativeCanary(ctx context.Context, call rootoci.Call, request rootoci.NativeCanaryRequest) (rootoci.NativeCanaryReceipt, error) {
	fail := func() (rootoci.NativeCanaryReceipt, error) {
		return rootoci.NativeCanaryReceipt{}, rootoci.ErrUnauthorized
	}
	if ctx == nil || service == nil || service.admission == nil || os.Geteuid() != 0 ||
		call.Operation() != rootoci.OperationMaterializeNativeCanary || !time.Now().Before(call.Deadline()) ||
		!entityid.Valid(request.OperationID) || !grantToken.MatchString(request.Node) {
		return fail()
	}
	for _, name := range ociclient.SecretUnsafeEnv {
		if _, set := os.LookupEnv(name); set {
			return fail()
		}
	}
	ctx, cancel := context.WithDeadline(ctx, call.Deadline())
	defer cancel()
	ctx = ociclient.WithRequestGuard(ctx, call.Guard)
	if call.Guard(ctx) != nil {
		return fail()
	}
	admitted, err := service.admission.nativeCanary(ctx, call, request)
	if err != nil {
		return fail()
	}
	ctx, stop := context.WithDeadline(ctx, admitted.deadline)
	defer stop()
	guard := func(ctx context.Context) error {
		if call.Guard(ctx) != nil || admitted.guard(ctx) != nil || call.Guard(ctx) != nil {
			return rootoci.ErrUnauthorized
		}
		return nil
	}
	if guard(ctx) != nil {
		return fail()
	}
	region, known := catalog.LookupName(admitted.intent.Cell)
	if !known {
		return fail()
	}
	factory, err := service.admission.factory.ForRegion(region.OCIRegion)
	if err != nil {
		return fail()
	}
	client, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		return fail()
	}
	client.HTTPClient = nativeCanaryDispatcher{next: client.HTTPClient, guard: guard}
	value, err := vaultsecret.ReadCurrent(ociclient.RequestContext(ctx), client, admitted.reference)
	if err != nil || guard(ctx) != nil {
		return fail()
	}
	expires := admitted.deadline
	if !value.ExpiresAt.IsZero() {
		expires = earlier(expires, value.ExpiresAt)
	}
	if !time.Now().Before(expires) {
		return fail()
	}
	return rootoci.NativeCanaryReceipt{Value: value.Value(), ExpiresAt: expires}, nil
}

type nativeCanaryDispatcher struct {
	next  common.HTTPRequestDispatcher
	guard func(context.Context) error
}

func (dispatcher nativeCanaryDispatcher) Do(request *http.Request) (*http.Response, error) {
	if dispatcher.guard(request.Context()) != nil {
		return nil, rootoci.ErrUnauthorized
	}
	return dispatcher.next.Do(request)
}

func (producer *rootMaterialAdmission) nativeCanary(ctx context.Context, call rootoci.Call, request rootoci.NativeCanaryRequest) (*rootNativeCanaryAdmission, error) {
	controller, _, err := producer.readers(ctx, call)
	if err != nil {
		return nil, err
	}
	config := controller.config
	ctx = config.credentialContext
	if !config.releaseDeadline.IsZero() {
		var cancel context.CancelFunc
		original := ctx
		ctx, cancel = context.WithDeadline(ctx, config.releaseDeadline)
		context.AfterFunc(original, cancel)
	}
	rootKV, err := config.JS.KeyValue(ctx, rootChainBucket)
	if err != nil {
		return nil, err
	}
	rootChain, err := rootKV.Get(ctx, rootChainKey)
	if err != nil || rootChain == nil || rootChain.Operation() != jetstream.KeyValuePut {
		return nil, rootoci.ErrUnauthorized
	}
	chain, err := trust.DecodeRootChain(rootChain.Value())
	if err != nil {
		return nil, err
	}
	roots, err := trust.VerifyRootChain(config.Specs.roots.genesis, config.Specs.roots.identity, chain)
	if err != nil || roots.Head != config.Specs.roots.reply("").Head || rootTrustChainCurrent(ctx, config.JS, rootChain) != nil {
		return nil, rootoci.ErrUnauthorized
	}
	intent, err := config.Delivery.NativeCanaryIntent(ctx, request.OperationID)
	if err != nil {
		return nil, err
	}
	lease, err := config.Mutations.AdmitCurrentLease(ctx, config.Specs.identity.DeploymentID, call.RuntimeID(), intent.AuthorityEpoch)
	if err != nil {
		return nil, err
	}
	session, err := config.Registrations.AdmitNativeCanarySession(ctx, request.Node)
	if err != nil {
		return nil, err
	}
	deadline := earlier(lease.Deadline(), session.Deadline())
	if original, ok := ctx.Deadline(); ok {
		deadline = earlier(deadline, original)
	}
	readCtx, stop := context.WithDeadline(ctx, deadline)
	context.AfterFunc(ctx, stop)
	spec, err := config.Specs.kv.Get(readCtx, cellSpecKey)
	if err != nil {
		return nil, err
	}
	verified, err := cellspec.VerifyHistorical(spec.Value(), config.Specs.roots.current(), config.Specs.identity)
	if err != nil || !verified.RootSigned || verified.ReleaseFence == nil || verified.ReleaseFence.Canary == nil {
		return nil, rootoci.ErrUnauthorized
	}
	history := &nativeHistory{js: config.JS, services: config.Specs, deliveries: config.Delivery}
	state, revision, err := history.load(readCtx, intent.Role)
	if err != nil {
		return nil, err
	}
	binding := state.Pending
	if state.Recovery != nil {
		binding = state.Recovery
	}
	if binding == nil || binding.Intent.OperationID != request.OperationID {
		return nil, rootoci.ErrUnauthorized
	}
	if !binding.Deadline.IsZero() {
		deadline = earlier(deadline, binding.Deadline)
	}
	if !request.Baseline {
		runningDeadline, err := nativeCanaryRunningDeadline(readCtx, config.Registrations, intent, request.Node)
		if err != nil {
			return nil, err
		}
		deadline = earlier(deadline, runningDeadline)
	}
	readCtx, bindingStop := context.WithDeadline(readCtx, deadline)
	context.AfterFunc(ctx, bindingStop)
	mark, err := nativeLeaderGet(readCtx, config.JS, releasechannel.Bucket, sequencedKey(intent.Role, intent.Generation))
	if err != nil {
		return nil, err
	}
	desired, err := nativeCanaryDesired(readCtx, config.Registrations, intent, request.Node)
	if err != nil {
		return nil, err
	}
	admitted := &rootNativeCanaryAdmission{original: readCtx, config: config, history: history,
		session: session, lease: lease, intent: intent, request: request, spec: spec, rootChain: rootChain, rootHead: roots.Head,
		historyRevision: revision, markRevision: mark.Sequence, mark: bytes.Clone(mark.Data), desired: desired,
		reference: verified.ReleaseFence.Canary.Credentials, deadline: deadline}
	if err := admitted.guard(readCtx); err != nil {
		return nil, err
	}
	return admitted, nil
}

func nativeCanaryDesired(ctx context.Context, reader *host.Reader, intent delivery.Intent, node string) ([]byte, error) {
	desired, err := reader.ListDesired(ctx, intent.Role)
	if err != nil {
		return nil, err
	}
	for _, target := range desired {
		if target.Node == node && !target.Withdrawn && target.Cell == intent.Cell && target.Environment == intent.Environment &&
			releaseOf(target.Generation) == intent.Generation && target.Digest == intent.ArtifactDigest &&
			delivery.ConfigDigestOf(target.Args, target.Env, target.Secrets) == intent.ConfigDigest {
			return protocol.EncodeJSON(target)
		}
	}
	return nil, rootoci.ErrUnauthorized
}

func (admitted *rootNativeCanaryAdmission) guard(ctx context.Context) error {
	if admitted == nil || ctx == nil || admitted.original == nil || admitted.original.Err() != nil || ctx.Err() != nil || !time.Now().Before(admitted.deadline) {
		return rootoci.ErrUnauthorized
	}
	ctx, cancel := context.WithDeadline(ctx, admitted.deadline)
	stop := context.AfterFunc(admitted.original, cancel)
	defer cancel()
	defer stop()
	if admitted.config.credentialSource == nil || admitted.config.credentialSource.Guard(ctx) != nil ||
		admitted.lease.Guard(ctx) != nil || admitted.session.Guard(ctx) != nil ||
		rootTrustChainCurrent(ctx, admitted.config.JS, admitted.rootChain) != nil ||
		controllerHostSpecCurrent(ctx, admitted.config.JS, admitted.config.Specs, admitted.spec, admitted.rootHead) != nil {
		return rootoci.ErrUnauthorized
	}
	registration, err := admitted.session.Registration()
	if err != nil || registration.Node != admitted.request.Node || registration.Cell != admitted.intent.Cell ||
		registration.Environment != admitted.intent.Environment || !slices.Contains(registration.Roles, admitted.intent.Role) {
		return rootoci.ErrUnauthorized
	}
	state, revision, err := admitted.history.load(ctx, admitted.intent.Role)
	if err != nil || revision != admitted.historyRevision {
		return rootoci.ErrUnauthorized
	}
	binding := state.Pending
	if state.Recovery != nil {
		binding = state.Recovery
	}
	fingerprint, err := admitted.intent.Fingerprint()
	if err != nil || binding == nil || binding.Fingerprint != fingerprint || state.Rejected == fingerprint {
		return rootoci.ErrUnauthorized
	}
	if _, err := admitted.history.profile(ctx, admitted.intent); err != nil {
		return err
	}
	if _, err := admitted.config.Delivery.RetainedArtifactClaim(ctx, admitted.intent.ArtifactDigest, admitted.intent.Role, admitted.intent.Environment); err != nil {
		return err
	}
	current, err := admitted.config.Delivery.NativeCanaryIntent(ctx, admitted.intent.OperationID)
	if err != nil {
		return err
	}
	confirmed, err := current.Fingerprint()
	if err != nil || confirmed != fingerprint {
		return rootoci.ErrUnauthorized
	}
	desired, err := nativeCanaryDesired(ctx, admitted.config.Registrations, admitted.intent, admitted.request.Node)
	if err != nil || !bytes.Equal(desired, admitted.desired) {
		return rootoci.ErrUnauthorized
	}
	key := sequencedKey(admitted.intent.Role, admitted.intent.Generation)
	mark, err := nativeLeaderGet(ctx, admitted.config.JS, releasechannel.Bucket, key)
	if err != nil || mark.Subject != "$KV."+releasechannel.Bucket+"."+key || mark.Sequence != admitted.markRevision ||
		mark.Header.Get("KV-Operation") != "" || mark.Header.Get(jetstream.MarkerReasonHeader) != "" || !bytes.Equal(mark.Data, admitted.mark) {
		return rootoci.ErrUnauthorized
	}
	var record canaryRecord
	if protocol.DecodeStrict(mark.Data, &record, 32<<10) != nil || record.Passed {
		return rootoci.ErrUnauthorized
	}
	if admitted.request.Baseline {
		if record.Node != "" {
			return rootoci.ErrUnauthorized
		}
		node, err := firstNativeCanaryNode(ctx, admitted.config, admitted.intent)
		if err != nil || node != admitted.request.Node {
			return rootoci.ErrUnauthorized
		}
	} else {
		deadline, err := nativeCanaryRunningDeadline(ctx, admitted.config.Registrations, admitted.intent, admitted.request.Node)
		if err != nil || record.Node != admitted.request.Node || deadline.Before(admitted.deadline) {
			return rootoci.ErrUnauthorized
		}
	}
	if admitted.session.Guard(ctx) != nil || admitted.lease.Guard(ctx) != nil || admitted.config.credentialSource.Guard(ctx) != nil ||
		admitted.original.Err() != nil || !time.Now().Before(admitted.deadline) {
		return rootoci.ErrUnauthorized
	}
	return ctx.Err()
}

func firstNativeCanaryNode(ctx context.Context, config containerMaterialConfig, intent delivery.Intent) (string, error) {
	desired, err := config.Registrations.ListDesired(ctx, intent.Role)
	if err != nil {
		return "", err
	}
	best, bestFenced := "", false
	for _, target := range desired {
		if target.Withdrawn || target.Cell != intent.Cell || target.Environment != intent.Environment || releaseOf(target.Generation) != intent.Generation {
			continue
		}
		key := fencedKey(target.Node)
		mark, err := nativeLeaderGet(ctx, config.JS, releasechannel.Bucket, key)
		fenced := err == nil
		if err != nil && !errors.Is(err, nats.ErrMsgNotFound) {
			return "", err
		}
		if fenced {
			if mark.Subject != "$KV."+releasechannel.Bucket+"."+key || mark.Sequence == 0 {
				return "", rootoci.ErrUnauthorized
			}
			fenced = mark.Header.Get("KV-Operation") == "" && mark.Header.Get(jetstream.MarkerReasonHeader) == ""
			if fenced {
				var record fenceRecord
				if protocol.DecodeStrict(mark.Data, &record, 64<<10) != nil {
					return "", rootoci.ErrUnauthorized
				}
			}
		}
		if best == "" || fenced && !bestFenced || fenced == bestFenced && target.Node < best {
			best, bestFenced = target.Node, fenced
		}
	}
	if best == "" {
		return "", rootoci.ErrUnauthorized
	}
	return best, nil
}

func nativeCanaryRunningDeadline(ctx context.Context, reader *host.Reader, intent delivery.Intent, node string) (time.Time, error) {
	statuses, err := reader.ListHosts(ctx)
	if err != nil {
		return time.Time{}, err
	}
	for _, status := range statuses {
		if status.Retired || status.Registration.Node != node || status.Registration.Cell != intent.Cell || status.Registration.Environment != intent.Environment {
			continue
		}
		for _, report := range status.Reports {
			if report.Node == node && report.Role == intent.Role && report.Digest == intent.ArtifactDigest && report.State == "running" &&
				releaseOf(report.Generation) == intent.Generation && time.Now().Before(report.ObservedAt.Add(host.ReportMaxAge)) {
				return report.ObservedAt.Add(host.ReportMaxAge), nil
			}
		}
	}
	return time.Time{}, rootoci.ErrUnauthorized
}
