//go:build linux

package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"reflect"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// The set retains absence too: an operation appearing during an effect invalidates
// an earlier selection that happened to contain no node operations.
type rootNodeOperations struct{ source *rootNodeOperationSource }
type rootNodeOperationAdmission struct {
	source   *rootNodeOperationSource
	op       nodeOp
	original protocol.Envelope
}

func (s rootNodeOperations) Operations() []rootNodeOperationAdmission {
	if s.source == nil {
		return nil
	}
	return slices.Clone(s.source.operations)
}
func (s rootNodeOperations) Deadline() time.Time {
	if s.source == nil {
		return time.Time{}
	}
	return s.source.deadline
}
func (s rootNodeOperations) Revalidate(ctx context.Context) error {
	if s.source == nil {
		return rootoci.ErrUnauthorized
	}
	return s.source.revalidate(ctx)
}
func (a rootNodeOperationAdmission) Node() string          { return a.op.Node }
func (a rootNodeOperationAdmission) From() string          { return a.op.From }
func (a rootNodeOperationAdmission) OperationID() string   { return a.original.OperationID }
func (a rootNodeOperationAdmission) Operation() string     { return a.op.Op }
func (a rootNodeOperationAdmission) RequestSHA256() string { return a.op.RequestSHA256 }
func (a rootNodeOperationAdmission) Deadline() time.Time   { return a.original.ExpiresAt }
func (a rootNodeOperationAdmission) Revalidate(ctx context.Context) error {
	if a.source == nil || a.original.ExpiresAt.IsZero() || !time.Now().Before(a.original.ExpiresAt) {
		return rootoci.ErrUnauthorized
	}
	return a.source.revalidate(ctx)
}

type rootNodeJournalPin struct {
	revision  uint64
	wire      []byte
	operation string
}

func (p rootNodeJournalPin) present() bool { return p.revision != 0 && p.operation == "" }
func (p rootNodeJournalPin) same(other rootNodeJournalPin) bool {
	return p.revision == other.revision && p.operation == other.operation && bytes.Equal(p.wire, other.wire)
}

type rootNodeOperationSource struct {
	call           rootoci.Call
	credentials    *rootsecret.ControllerReader
	js             jetstream.JetStream
	snapshot       rootResourceSnapshot
	lease          authority.Snapshot
	lifetime       context.Context
	deadline       time.Time
	pins           map[string]rootNodeJournalPin
	operations     []rootNodeOperationAdmission
	journalCreated time.Time
	journalConfig  jetstream.StreamConfig
}

// These exact-key reads always reach the stream leader, including negative reads.
// A retained deletion is pinned as absence; unknown marker/history fails closed.
func readRootNodeJournal(ctx context.Context, js jetstream.JetStream, key string) (rootNodeJournalPin, error) {
	options := js.Options()
	var opts []nats.JSOpt
	if options.Domain != "" {
		opts = append(opts, nats.Domain(options.Domain))
	} else if options.APIPrefix != "" {
		opts = append(opts, nats.APIPrefix(options.APIPrefix))
	}
	reader, err := js.Conn().JetStream(opts...)
	if err != nil {
		return rootNodeJournalPin{}, err
	}
	subject := "$KV." + releasechannel.Bucket + "." + key
	msg, err := reader.GetLastMsg("KV_"+releasechannel.Bucket, subject, nats.Context(ctx))
	if errors.Is(err, nats.ErrMsgNotFound) {
		return rootNodeJournalPin{}, nil
	}
	if err != nil {
		return rootNodeJournalPin{}, err
	}
	if msg == nil || msg.Subject != subject || msg.Sequence == 0 || msg.Time.IsZero() || msg.Header.Get(jetstream.MarkerReasonHeader) != "" || len(msg.Data) > 1<<20 {
		return rootNodeJournalPin{}, errors.New("node operation journal has corrupt or unknown history")
	}
	operation := msg.Header.Get("KV-Operation")
	if operation != "" && operation != "DEL" && operation != "PURGE" || operation == "" && len(msg.Data) == 0 {
		return rootNodeJournalPin{}, errors.New("node operation journal has an invalid current entry")
	}
	return rootNodeJournalPin{revision: msg.Sequence, wire: bytes.Clone(msg.Data), operation: operation}, nil
}

func (s *rootNodeOperationSource) read(ctx context.Context, key string) (rootNodeJournalPin, error) {
	pin, err := readRootNodeJournal(ctx, s.js, key)
	if err != nil {
		return pin, err
	}
	if previous, ok := s.pins[key]; ok && !previous.same(pin) {
		return pin, errors.New("node operation source changed while selecting finite operations")
	}
	s.pins[key] = pin
	return pin, nil
}

func (producer *rootMaterialAdmission) nodeOperations(ctx context.Context, call rootoci.Call, cell, role string) (rootNodeOperations, error) {
	fail := func(err error) (rootNodeOperations, error) { return rootNodeOperations{}, err }
	if os.Geteuid() != 0 || producer == nil || producer.ownhost == nil || producer.factory == nil || cell == "" || role == "" || call.RuntimeID() == "" {
		return fail(rootoci.ErrUnauthorized)
	}
	if err := call.Guard(ctx); err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithDeadline(ctx, call.Deadline())
	success := false
	defer func() {
		if !success {
			cancel()
		}
	}()
	cfg, err := LoadConfig(controllerConfigDirectory + "/" + controllerConfigFilename)
	if err != nil {
		return fail(err)
	}
	credentials, err := rootsecret.OpenControllerReader(ctx)
	if err != nil {
		return fail(err)
	}
	conn, credentialContext := credentials.Conn(), credentials.Context()
	if conn == nil || credentialContext == nil || credentialContext.Done() == nil || credentialContext.Err() != nil {
		if conn != nil {
			conn.Close()
		}
		return fail(rootoci.ErrUnauthorized)
	}
	defer func() {
		if !success {
			conn.Close()
		}
	}()
	credentialDeadline, ok := credentialContext.Deadline()
	if !ok || !time.Now().Before(credentialDeadline) {
		return fail(rootoci.ErrUnauthorized)
	}
	ctx, credentialCancel := context.WithDeadline(ctx, credentialDeadline)
	context.AfterFunc(credentialContext, credentialCancel)
	context.AfterFunc(ctx, conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		return fail(err)
	}
	snapshot, err := readRootResourceSnapshot(ctx, cfg, js)
	if err != nil {
		return fail(err)
	}
	if cell != cfg.NATS.Cell {
		return fail(rootoci.ErrUnauthorized)
	}
	fence, addresses := snapshot.services.releaseFence()
	if fence == nil || !slices.ContainsFunc(fence.BackendSets, func(set cellspec.FencedSet) bool { return set.Role == role }) {
		return fail(errors.New("node operation role has no exact signed fenced set"))
	}
	observed, err := authority.Observe(ctx, js, cell)
	if err != nil {
		return fail(err)
	}
	if !observed.Ready || observed.Epoch == 0 || observed.Revision == 0 || observed.DeploymentID != snapshot.services.identity.DeploymentID || observed.CandidateID != call.RuntimeID() {
		return fail(authority.ErrFenced)
	}
	deadline := minResourceDeadline(call.Deadline(), observed.ExpiresAt, snapshot.specExpiresAt, credentialDeadline)
	if deadline.IsZero() || !time.Now().Before(deadline) {
		return fail(authority.ErrFenced)
	}
	ctx, sourceCancel := context.WithDeadline(ctx, deadline)
	context.AfterFunc(ctx, conn.Close)
	source := &rootNodeOperationSource{call: call, credentials: credentials, js: js, snapshot: snapshot, lease: observed,
		lifetime: ctx, deadline: deadline, pins: make(map[string]rootNodeJournalPin)}
	journal, err := js.Stream(ctx, "KV_"+releasechannel.Bucket)
	if err != nil {
		return fail(err)
	}
	info, err := journal.Info(ctx)
	if err != nil {
		return fail(err)
	}
	if info == nil || info.Created.IsZero() {
		return fail(errors.New("node operation journal has no retained stream identity"))
	}
	source.journalCreated, source.journalConfig = info.Created, info.Config
	// Only the finite node names from the authenticated current spec can select work.
	for node := range addresses {
		progress, err := source.read(ctx, nodeOpKey(node))
		if err != nil {
			return fail(err)
		}
		held, err := source.read(ctx, fencedKey(node))
		if err != nil {
			return fail(err)
		}
		var holds fenceRecord
		if held.present() {
			if err := json.Unmarshal(held.wire, &holds, json.RejectUnknownMembers(true)); err != nil {
				return fail(err)
			}
		}
		operationHeld := held.present() && slices.ContainsFunc(holds.holders(), func(holder string) bool { return holder == holdMaintenance || holder == holdOperation })
		if !progress.present() {
			if operationHeld {
				return fail(errors.New("node hold has no retained signed operation"))
			}
			continue
		}
		var op nodeOp
		if err := json.Unmarshal(progress.wire, &op, json.RejectUnknownMembers(true)); err != nil {
			return fail(err)
		}
		if !entityid.Valid(op.ID) || op.Node != node || (op.State != nodeOpQueued && op.State != nodeOpRunning && op.State != nodeOpDone && op.State != nodeOpFailed) {
			return fail(errors.New("node operation progress has invalid identity or state"))
		}
		if !op.active() && !operationHeld {
			continue
		}
		archive, err := source.read(ctx, nodeOperationRequestKey(op.ID))
		if err != nil {
			return fail(err)
		}
		if !archive.present() || archive.revision != op.RequestRevision {
			return fail(errors.New("original signed node operation is missing or replaced"))
		}
		var record nodeOperationRequestRecord
		if err := json.Unmarshal(archive.wire, &record, json.RejectUnknownMembers(true)); err != nil {
			return fail(err)
		}
		original, err := matchNodeOperationRequest(op, record)
		if err != nil {
			return fail(err)
		}
		// Unverified time may only shorten the context before later policy/source waits.
		if original.ExpiresAt.IsZero() || !time.Now().Before(original.ExpiresAt) {
			return fail(protocol.ErrExpired)
		}
		if original.ExpiresAt.Before(source.deadline) {
			source.deadline = original.ExpiresAt
			ctx, sourceCancel = context.WithDeadline(ctx, original.ExpiresAt)
			context.AfterFunc(ctx, conn.Close)
			source.lifetime = ctx
		}
		if op.From != "" {
			if _, err := source.read(ctx, nodeOpKey(op.From)); err != nil {
				return fail(err)
			}
			if _, err := source.read(ctx, fencedKey(op.From)); err != nil {
				return fail(err)
			}
		}
		if record.Policy != nodeOperationPins(snapshot) {
			return fail(errors.New("node operation policy pins are no longer current"))
		}
		policy, err := nodeOperationPolicy(cfg, snapshot)
		if err != nil {
			return fail(err)
		}
		if _, _, err := verifyNodeOperationRequest(record.Wire, cell, observed.Epoch, policy, time.Now().UTC()); err != nil {
			return fail(err)
		}
		source.operations = append(source.operations, rootNodeOperationAdmission{source: source, op: op, original: original})
	}
	if err := source.revalidate(ctx); err != nil {
		sourceCancel()
		return fail(err)
	}
	success = true
	return rootNodeOperations{source: source}, nil
}

func (s *rootNodeOperationSource) revalidate(ctx context.Context) error {
	if s == nil || s.lifetime == nil || s.lifetime.Err() != nil || s.deadline.IsZero() || !time.Now().Before(s.deadline) {
		return rootoci.ErrUnauthorized
	}
	ctx, cancel := context.WithDeadline(ctx, s.deadline)
	defer cancel()
	if err := s.call.Guard(ctx); err != nil {
		return err
	}
	if err := s.credentials.Guard(ctx); err != nil {
		return err
	}
	cfg, err := LoadConfig(controllerConfigDirectory + "/" + controllerConfigFilename)
	if err != nil {
		return err
	}
	snapshot, err := readRootResourceSnapshot(ctx, cfg, s.js)
	if err != nil || !s.snapshot.same(snapshot) {
		return errors.Join(errors.New("node operation signed policy changed"), err)
	}
	current, err := authority.Observe(ctx, s.js, s.lease.Scope)
	if err != nil || !current.Ready || current.Scope != s.lease.Scope || current.DeploymentID != s.lease.DeploymentID || current.CandidateID != s.lease.CandidateID ||
		current.OwnerID != s.lease.OwnerID || current.Epoch != s.lease.Epoch || current.Revision < s.lease.Revision || !time.Now().Before(current.ExpiresAt) {
		return errors.Join(authority.ErrFenced, err)
	}
	journal, err := s.js.Stream(ctx, "KV_"+releasechannel.Bucket)
	if err != nil {
		return err
	}
	info, err := journal.Info(ctx)
	if err != nil {
		return err
	}
	if info == nil || !s.journalCreated.Equal(info.Created) || !reflect.DeepEqual(s.journalConfig, info.Config) {
		return errors.Join(errors.New("node operation journal was replaced or reconfigured"), err)
	}
	for key, expected := range s.pins {
		current, err := readRootNodeJournal(ctx, s.js, key)
		if err != nil || !expected.same(current) {
			return errors.Join(errors.New("node operation source changed"), err)
		}
	}
	if !time.Now().Before(s.deadline) || s.lifetime.Err() != nil {
		return rootoci.ErrUnauthorized
	}
	if err := ociclient.LimitAdmission(ctx, s.deadline); err != nil {
		return err
	}
	if err := s.credentials.Guard(ctx); err != nil {
		return err
	}
	return s.call.Guard(ctx)
}
