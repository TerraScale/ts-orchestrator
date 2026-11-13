//go:build linux

package app

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
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

func (p rootNodeJournalPin) same(other rootNodeJournalPin) bool {
	return p.revision == other.revision && p.operation == other.operation && bytes.Equal(p.wire, other.wire)
}

type rootNodeOperationSource struct {
	call           rootoci.Call
	credentials    *rootsecret.ControllerReader
	js             jetstream.JetStream
	snapshot       rootResourceSnapshot
	cfg            Config
	lease          authority.Snapshot
	lifetime       context.Context
	deadline       time.Time
	pins           map[string]rootNodeJournalPin
	operations     []rootNodeOperationAdmission
	journalCreated time.Time
	journalConfig  jetstream.StreamConfig
	// release ends the shortened lifetimes; they otherwise end at their own deadlines.
	release []context.CancelFunc
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
