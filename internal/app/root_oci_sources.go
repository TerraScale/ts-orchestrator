package app

import (
	"bytes"
	"context"
	"errors"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// These handles are opened in root from its independently verified in-memory
// credentials. No ordinary controller pointer or private credential file enters.
type rootControllerSources struct {
	conn        *nats.Conn
	lease       context.Context
	credentials *rootsecret.ControllerReader
	js          jetstream.JetStream
	policy      signerPolicy
	specs       *specRegistry
	intents     *delivery.Service
	mutations   *authority.Reader
	hosts       *host.Reader
	members     placement.MemberPinReader
}

func rootTrustChainCurrent(ctx context.Context, js jetstream.JetStream, entry jetstream.KeyValueEntry) error {
	if js == nil || js.Conn() == nil || entry == nil || entry.Revision() == 0 {
		return errors.New("root trust source requires the original current revision")
	}
	options := js.Options()
	var opts []nats.JSOpt
	if options.Domain != "" {
		opts = append(opts, nats.Domain(options.Domain))
	} else if options.APIPrefix != "" {
		opts = append(opts, nats.APIPrefix(options.APIPrefix))
	}
	reader, err := js.Conn().JetStream(opts...)
	if err != nil {
		return err
	}
	subject := "$KV." + rootChainBucket + "." + rootChainKey
	latest, err := reader.GetLastMsg("KV_"+rootChainBucket, subject, nats.Context(ctx))
	if err != nil {
		return err
	}
	if latest == nil || latest.Subject != subject || latest.Sequence != entry.Revision() ||
		latest.Header.Get("KV-Operation") != "" || latest.Header.Get(jetstream.MarkerReasonHeader) != "" ||
		len(latest.Data) == 0 || len(latest.Data) > trust.MaxRootChainBytes || !bytes.Equal(latest.Data, entry.Value()) || ctx.Err() != nil {
		return errors.New("original root trust source is no longer current at its stream leader")
	}
	return nil
}

func openRootControllerSources(ctx context.Context, cfg Config) (_ *rootControllerSources, resultErr error) {
	if os.Geteuid() != 0 || ctx == nil || ctx.Err() != nil {
		return nil, errors.New("regional source readers require the live root runtime")
	}
	credentials, err := rootsecret.OpenControllerReader(ctx)
	if err != nil {
		return nil, err
	}
	conn, lease := credentials.Conn(), credentials.Context()
	if lease == nil || lease.Done() == nil || lease.Err() != nil {
		conn.Close()
		return nil, errors.New("root source credentials have no original live lifetime")
	}
	defer func() {
		if resultErr != nil {
			conn.Close()
		}
	}()
	js, err := jetstream.New(conn)
	if err != nil {
		return nil, err
	}
	specs, policy, err := runtimeRegistryPolicy(ctx, cfg, js)
	if err != nil {
		return nil, err
	}
	intents, err := delivery.ConnectClient(ctx, delivery.Config{Conn: conn, JS: js, Cell: cfg.NATS.Cell,
		Verifier: policy.codec, Authorize: policy.authorizeIntent, ArtifactVerifier: policy.codec, AuthorizeArtifact: policy.authorizeArtifact})
	if err != nil {
		return nil, err
	}
	mutations, err := authority.OpenReader(ctx, js, cfg.NATS.Cell)
	if err != nil {
		return nil, err
	}
	hosts, err := host.NewReader(ctx, host.ReaderConfig{Cell: cfg.NATS.Cell, Conn: conn, JS: js,
		StateReplicas: cfg.NATS.Replicas, HostMutations: mutations})
	if err != nil {
		return nil, err
	}
	members, err := placement.OpenMemberPinReader(ctx, js, cfg.NATS.Cell, cfg.NATS.Replicas)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || conn.IsClosed() {
		return nil, errors.New("root regional source connection ended during admission")
	}
	return &rootControllerSources{conn: conn, lease: lease, credentials: credentials, js: js, policy: policy, specs: specs, intents: intents,
		mutations: mutations, hosts: hosts, members: members}, nil
}
