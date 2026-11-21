package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/regionalowner"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func ownerStoreCluster(ctx context.Context, work string) (jetstream.JetStream, jetstream.JetStream, func() (server.RaftNode, func(context.Context)), func(), func()) {
	password, ordinary, monitor := rand.Text(), rand.Text(), rand.Text()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	port := listener.Addr().(*net.TCPAddr).Port
	must(listener.Close())
	seed, err := url.Parse(fmt.Sprintf("nats-route://127.0.0.1:%d", port))
	must(err)
	var brokers []*server.Server
	var configs []*server.Options
	startBroker := func(options *server.Options) *server.Server {
		broker, err := server.NewServer(options.Clone())
		must(err)
		go broker.Start()
		require(broker.ReadyForConnections(5*time.Second), "owner broker did not start")
		return broker
	}
	for i := range 3 {
		options := &server.Options{}
		must(options.ProcessConfigString("accounts { OWNER { jetstream: enabled }, ORCH {}, SYS {} }\nsystem_account: SYS"))
		for _, account := range options.Accounts {
			switch account.Name {
			case "OWNER":
				options.Users = append(options.Users, &server.User{Username: "authority", Password: password, Account: account})
			case "ORCH":
				options.Users = append(options.Users, &server.User{Username: "orch", Password: ordinary, Account: account})
			case "SYS":
				options.Users = append(options.Users, &server.User{Username: "monitor", Password: monitor, Account: account})
			}
		}
		options.Host, options.Port, options.NoLog, options.NoSigs = "127.0.0.1", -1, true, true
		options.ServerName, options.StoreDir = fmt.Sprintf("owner-%d", i), filepath.Join(work, fmt.Sprint(i))
		options.JetStream, options.SyncAlways = true, true
		options.Cluster = server.ClusterOpts{Name: "owner-journey", Host: "127.0.0.1", Port: -1}
		if i == 0 {
			options.Cluster.Port = port
		}
		options.Routes = []*url.URL{seed}
		broker := startBroker(options)
		options.Cluster.Port = broker.ClusterAddr().Port
		configs = append(configs, options)
		brokers = append(brokers, broker)
	}
	connect := func(index int, user, pass string) (jetstream.JetStream, *nats.Conn) {
		nc, err := nats.Connect(brokers[index].ClientURL(), nats.UserInfo(user, pass), nats.NoReconnect())
		must(err)
		js, err := jetstream.New(nc)
		must(err)
		return js, nc
	}
	js, admin := connect(0, "authority", password)
	untrusted, orch := connect(0, "orch", ordinary)
	monitorAt := func(index int) (*nats.Conn, *nats.Subscription) {
		_, system := connect(index, "monitor", monitor)
		events, err := system.SubscribeSync("$SYS.SERVER.*.STATSZ")
		must(err)
		must(system.Flush())
		return system, events
	}
	system, events := monitorAt(0)
	ready, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
readyCluster:
	for {
		for _, broker := range brokers {
			if len(broker.JetStreamClusterPeers()) == 3 {
				break readyCluster
			}
		}
		_, err := events.NextMsgWithContext(ready)
		must(err)
	}
	stream, err := js.CreateStream(ready, regionalowner.StreamConfig())
	must(err)
	info, err := stream.Info(ready)
	must(err)
	primary := -1
	for i, broker := range brokers {
		if broker.Name() == info.Cluster.Leader {
			primary = i
		}
	}
	require(primary >= 0, "owner stream is missing a fixture leader")
	if primary != 0 {
		admin.Close()
		js, admin = connect(primary, "authority", password)
		system.Close()
		system, events = monitorAt(primary)
	}
	loseQuorum := func() {
		for i, broker := range brokers {
			if i != primary {
				broker.Shutdown()
				broker.WaitForShutdown()
			}
		}
	}
	pauseReplication := func() (server.RaftNode, func(context.Context)) {
		var leader server.RaftNode
		for _, node := range brokers[primary].RaftNodes() {
			if node.Group() != "_meta_" && node.Leader() {
				leader = node
			}
		}
		require(leader != nil && leader.ClusterSize() == 3, "owner stream has no three-voter leader")
		loseQuorum()
		require(leader.Leader() && leader.ClusterSize() == 3, "the isolated stream lost its proposing leader")
		return leader, func(ctx context.Context) {
			for i, options := range configs {
				if i != primary {
					brokers[i] = startBroker(options)
				}
			}
			for {
				current, meta, fullMembership := 0, 0, false
				for _, broker := range brokers {
					fullMembership = fullMembership || len(broker.JetStreamClusterPeers()) == 3
					for _, node := range broker.RaftNodes() {
						if node.Leaderless() || !node.Current() {
							continue
						}
						switch node.Group() {
						case "_meta_":
							meta++
						case leader.Group():
							current++
						}
					}
				}
				if fullMembership && meta == 3 && current == 3 {
					return
				}
				_, err := events.NextMsgWithContext(ctx)
				must(err)
			}
		}
	}
	cleanup := func() {
		admin.Close()
		orch.Close()
		system.Close()
		for _, broker := range brokers {
			broker.Shutdown()
			broker.WaitForShutdown()
		}
	}
	return js, untrusted, pauseReplication, loseQuorum, cleanup
}

func ownerEpochCase(ctx context.Context, work, region, managerState, foreignState string) {
	js, untrusted, pauseReplication, loseQuorum, cleanup := ownerStoreCluster(ctx, filepath.Join(work, "owner-store"))
	defer cleanup()
	authorityKey, authority, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	authenticate := func(chain [][]byte, message, signature []byte) (regionalowner.Manager, error) {
		id, err := swarmruntime.VerifyRegionalManager(managerState, chain, message, signature)
		if err != nil {
			return regionalowner.Manager{}, err
		}
		leaf, err := x509.ParseCertificate(chain[0])
		if err != nil {
			return regionalowner.Manager{}, err
		}
		return regionalowner.Manager{Node: id, Cluster: leaf.Subject.Organization[0]}, nil
	}
	open := func(access jetstream.JetStream) *regionalowner.Store {
		store, err := regionalowner.Open(ctx, access, region, authorityKey, authenticate)
		must(err)
		return store
	}
	store := open(js)
	unauthorized, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	_, err = regionalowner.Open(unauthorized, untrusted, region, authorityKey, authenticate)
	require(err != nil, "ordinary ORCH connection opened the private owner stream")
	node, err := swarmruntime.LocalNodeID(ctx, managerState)
	must(err)
	client, control, err := swarmruntime.DialControl(managerState)
	must(err)
	defer control.Close()
	observed, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: node})
	must(err)
	require(observed.Node.Role == api.NodeRoleManager && observed.Node.Spec.Membership == api.NodeMembershipAccepted,
		"the membership fixture must admit a real Swarm manager")
	chain, _, err := swarmruntime.SignRegional(managerState, []byte("owner journey membership"))
	must(err)
	leaf, err := x509.ParseCertificate(chain[0])
	must(err)
	view := regionalowner.Membership{Region: region, Cluster: leaf.Subject.Organization[0], Epoch: 1,
		Managers: []string{node}, ValidUntil: time.Now().Add(time.Minute)}
	signView := func(view regionalowner.Membership, key ed25519.PrivateKey) []byte {
		wire, err := regionalowner.MembershipMessage(view)
		must(err)
		return ed25519.Sign(key, wire)
	}
	_, fakeAuthority, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	_, err = store.InstallMembership(ctx, view, signView(view, fakeAuthority))
	require(errors.Is(err, regionalowner.ErrFenced), "unauthenticated membership was accepted")
	admitted, err := store.InstallMembership(ctx, view, signView(view, authority))
	must(err)

	oldPublic, old, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	nextPublic, successor, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	request := regionalowner.Request{Operation: regionalowner.Acquire, Region: view.Region, Cluster: view.Cluster, Node: node,
		Session: oldPublic, MembershipEpoch: view.Epoch, OwnerEpoch: admitted.Lease.OwnerEpoch, Sequence: 1}
	proofFor := func(req regionalowner.Request, key ed25519.PrivateKey, signer string) regionalowner.Proof {
		wire, err := regionalowner.RequestMessage(req)
		must(err)
		proof := regionalowner.Proof{SessionSignature: ed25519.Sign(key, wire)}
		if signer != "" {
			proof.ManagerChain, proof.ManagerSignature, err = swarmruntime.SignRegional(signer, wire)
			must(err)
		}
		return proof
	}
	apply := func(ctx context.Context, req regionalowner.Request, key ed25519.PrivateKey, signer string) (regionalowner.Snapshot, error) {
		return store.Apply(ctx, req, proofFor(req, key, signer))
	}
	_, err = apply(ctx, request, old, foreignState)
	require(errors.Is(err, regionalowner.ErrFenced), "another region's certificate impersonated the admitted manager")
	lease, err := apply(ctx, request, old, managerState)
	must(err)
	logStep("admitted regional manager acquires a quorum-persisted owner session")

	impostor := request
	impostor.Session, impostor.OwnerEpoch = nextPublic, lease.Lease.OwnerEpoch
	_, err = apply(ctx, impostor, successor, managerState)
	require(errors.Is(err, regionalowner.ErrFenced), "another process of the same manager took a live lease")
	renew := request
	renew.Operation, renew.OwnerEpoch, renew.Sequence = regionalowner.Renew, lease.Lease.OwnerEpoch, 2
	_, err = apply(ctx, renew, successor, "")
	require(errors.Is(err, regionalowner.ErrFenced), "same-ID impostor renewed without its session key")
	renewed, err := apply(ctx, renew, old, "")
	must(err)
	require(renewed.Revision > lease.Revision && renewed.Lease.ExpiresAt.After(lease.Lease.ExpiresAt), "the live owner did not extend its confirmed lease")
	publish := renew
	publish.Operation, publish.Sequence = regionalowner.Publish, 3
	publish.Digest = sha256.Sum256([]byte("regional owner observation"))
	published, err := apply(ctx, publish, old, "")
	must(err)
	require(published.Lease.Digest == publish.Digest && published.Revision > renewed.Revision, "valid publication did not reach quorum")

	revoked := view
	revoked.Epoch++
	revoked.Managers = nil
	renew.Sequence, publish.Sequence = 4, 4
	resume := make(chan struct{})
	racing := make(chan error, 2)
	arrived := make(chan struct{}, 2)
	held := open(ownerPublisher{JetStream: js, send: func(ctx context.Context, subject string, data []byte, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		arrived <- struct{}{}
		select {
		case <-resume:
			return js.Publish(ctx, subject, data, opts...)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}})
	for _, request := range []regionalowner.Request{renew, publish} {
		go func() {
			_, err := held.Apply(ctx, request, proofFor(request, old, ""))
			racing <- err
		}()
	}
	for range 2 {
		select {
		case <-arrived:
		case err := <-racing:
			panic(fmt.Sprintf("owner did not reach its previously valid CAS: %v", err))
		case <-ctx.Done():
			panic(ctx.Err())
		}
	}
	reassigned, err := store.InstallMembership(ctx, revoked, signView(revoked, authority))
	must(err)
	require(reassigned.Lease.Node == "" && reassigned.Lease.Digest == ([32]byte{}) && reassigned.Revision > published.Revision,
		"membership epoch transition retained previous owner evidence")
	close(resume)
	for range 2 {
		require(errors.Is(<-racing, regionalowner.ErrConflict), "an old read wrote over a committed revocation")
	}
	for _, stale := range []regionalowner.Request{renew, publish} {
		_, err := apply(ctx, stale, old, "")
		require(errors.Is(err, regionalowner.ErrFenced), fmt.Sprintf("old owner could %s after a membership change: %v", stale.Operation, err))
	}
	_, err = store.InstallMembership(ctx, view, signView(view, authority))
	require(errors.Is(err, regionalowner.ErrFenced), "the old signed membership view replaced revocation")
	impostor.MembershipEpoch = revoked.Epoch
	_, err = apply(ctx, impostor, successor, managerState)
	require(errors.Is(err, regionalowner.ErrFenced), "a valid manager certificate bypassed revocation")
	view.Epoch = revoked.Epoch + 1
	readmitted, err := store.InstallMembership(ctx, view, signView(view, authority))
	must(err)
	impostor.MembershipEpoch = view.Epoch
	replacement, err := apply(ctx, impostor, successor, managerState)
	must(err)
	require(replacement.Lease.OwnerEpoch == lease.Lease.OwnerEpoch+1 && replacement.Revision > readmitted.Revision, "successor did not get a newer epoch")
	_, err = apply(ctx, publish, old, "")
	require(errors.Is(err, regionalowner.ErrFenced), "old owner published after reassignment")
	logStep("same-ID impostor is rejected and an authenticated membership advance fences stale renewal and publication before reassignment")

	valid := impostor
	valid.Operation, valid.OwnerEpoch, valid.Sequence = regionalowner.Publish, replacement.Lease.OwnerEpoch, 2
	valid.Digest = publish.Digest
	retired := valid
	retired.Session = oldPublic
	_, err = apply(ctx, retired, old, "")
	require(errors.Is(err, regionalowner.ErrFenced), "retired process signed current headers and published")
	retired.Operation, retired.Digest = regionalowner.Renew, [32]byte{}
	_, err = apply(ctx, retired, old, "")
	require(errors.Is(err, regionalowner.ErrFenced), "retired process signed current headers and renewed")
	logStep("revocation wins CAS against already-read renew and publish, and a retired key cannot use the current epochs")
	committed, err := apply(ctx, valid, successor, "")
	must(err)
	require(committed.Lease.Digest == valid.Digest, "successor could not publish")
	candidate := valid
	candidate.Operation, candidate.Sequence, candidate.Digest = regionalowner.Renew, valid.Sequence+1, [32]byte{}
	delayedOwnerRenewal(ctx, js, open, pauseReplication, candidate, proofFor(candidate, successor, ""), committed.Lease.ExpiresAt)
	valid.Sequence += 2
	_, err = apply(ctx, valid, successor, "")
	require(errors.Is(err, regionalowner.ErrFenced), "old session published after its late candidate was stored")
	acquire := candidate
	acquire.Operation, acquire.Sequence = regionalowner.Acquire, 1
	_, err = apply(ctx, acquire, successor, managerState)
	require(errors.Is(err, regionalowner.ErrFenced), "expired session reacquired with the same key")
	freshPublic, fresh, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	acquire.Session = freshPublic
	freshLease, err := apply(ctx, acquire, fresh, managerState)
	must(err)
	require(freshLease.Lease.OwnerEpoch == committed.Lease.OwnerEpoch+1, "fresh admission did not advance the fenced owner epoch")
	logStep("late renewal reaches quorum after expiry, stays a candidate, and requires a fresh fenced session")
	loseQuorum()
	quorum, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	valid.Session, valid.OwnerEpoch, valid.Sequence = freshPublic, freshLease.Lease.OwnerEpoch, 2
	_, err = apply(quorum, valid, fresh, "")
	require(errors.Is(err, regionalowner.ErrQuorum), fmt.Sprintf("publication without quorum did not fail closed: %v", err))
	logStep("the current owner cannot publish after two of the three store replicas stop")
}

type ownerPublisher struct {
	jetstream.JetStream
	send func(context.Context, string, []byte, ...jetstream.PublishOpt) (*jetstream.PubAck, error)
}

func (p ownerPublisher) Publish(ctx context.Context, subject string, data []byte, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	return p.send(ctx, subject, data, opts...)
}

func delayedOwnerRenewal(ctx context.Context, js jetstream.JetStream, open func(jetstream.JetStream) *regionalowner.Store,
	pause func() (server.RaftNode, func(context.Context)), request regionalowner.Request, proof regionalowner.Proof, expiry time.Time,
) {
	type reply struct {
		ack *jetstream.PubAck
		err error
	}
	brokerCtx, cancel := context.WithDeadline(ctx, expiry.Add(5*time.Second))
	defer cancel()
	proposed := make(chan reply, 1)
	arrived, proceed := make(chan struct{}), make(chan struct{})
	held := open(ownerPublisher{JetStream: js, send: func(ctx context.Context, subject string, data []byte, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		close(arrived)
		select {
		case <-proceed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		go func() {
			ack, err := js.Publish(brokerCtx, subject, data, opts...)
			proposed <- reply{ack, err}
		}()
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	start := time.NewTimer(time.Until(expiry.Add(-2 * time.Second)))
	defer start.Stop()
	select {
	case <-start.C:
	case <-ctx.Done():
		panic(ctx.Err())
	}
	completed := make(chan error, 1)
	go func() {
		_, err := held.Apply(ctx, request, proof)
		completed <- err
	}()
	select {
	case <-arrived:
	case err := <-completed:
		panic(fmt.Sprintf("delayed owner did not reach renewal proposal: %v", err))
	case <-ctx.Done():
		panic(ctx.Err())
	}
	leader, resume := pause()
	pindex, committed, _ := leader.Progress()
	close(proceed)
	deadline, stop := context.WithDeadline(ctx, expiry)
	defer stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	var pending uint64
	for pending == 0 {
		index, commit, _ := leader.Progress()
		require(commit == committed, "the renewal committed while its replication was held")
		if index > pindex {
			pending = index
			break
		}
		select {
		case <-tick.C:
		case <-deadline.Done():
			panic("the renewal was not proposed before the prior expiry")
		}
	}
	require(time.Now().Before(expiry), "the proposal was first observed after the previous expiry")
	err := <-completed
	require(errors.Is(err, regionalowner.ErrQuorum) && !time.Now().Before(expiry), fmt.Sprintf("renewal did not time out at its old deadline: %v", err))
	_, commit, _ := leader.Progress()
	require(commit < pending, "quorum committed the proposal before replication resumed")
	recovered, finish := context.WithTimeout(ctx, 10*time.Second)
	defer finish()
	resume(recovered)
	committedReply := <-proposed
	must(committedReply.err)
	stream, err := js.Stream(recovered, regionalowner.StreamConfig().Name)
	must(err)
	stored, err := stream.GetLastMsgForSubject(recovered, "ts.owner."+request.Region)
	must(err)
	var record struct {
		Lease struct {
			ExpiresAt time.Time
		}
		Candidate *struct {
			Sequence  uint64
			ExpiresAt time.Time
		}
		Confirmation json.RawMessage
	}
	must(json.Unmarshal(stored.Data, &record))
	require(stored.Sequence == committedReply.ack.Sequence && stored.Time.Before(expiry) && record.Lease.ExpiresAt.Equal(expiry) &&
		record.Candidate != nil && record.Candidate.Sequence == request.Sequence && record.Candidate.ExpiresAt.After(expiry) &&
		string(record.Confirmation) == "null", "the late quorum write did not preserve the old expiry with an unconfirmed candidate")
	fmt.Printf("renewal candidate raft index %d, commit index %d at expiry, stored revision %d after replication resumed\n", pending, commit, stored.Sequence)
}
