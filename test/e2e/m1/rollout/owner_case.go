package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
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

func ownerStoreCluster(ctx context.Context, work string) (jetstream.JetStream, jetstream.JetStream, func(), func()) {
	password, ordinary, monitor := rand.Text(), rand.Text(), rand.Text()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	port := listener.Addr().(*net.TCPAddr).Port
	must(listener.Close())
	seed, err := url.Parse(fmt.Sprintf("nats-route://127.0.0.1:%d", port))
	must(err)
	var brokers []*server.Server
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
		broker, err := server.NewServer(options)
		must(err)
		go broker.Start()
		require(broker.ReadyForConnections(5*time.Second), "owner broker did not start")
		brokers = append(brokers, broker)
	}
	connect := func(user, pass string) (jetstream.JetStream, *nats.Conn) {
		nc, err := nats.Connect(brokers[0].ClientURL(), nats.UserInfo(user, pass), nats.NoReconnect())
		must(err)
		js, err := jetstream.New(nc)
		must(err)
		return js, nc
	}
	js, admin := connect("authority", password)
	untrusted, orch := connect("orch", ordinary)
	_, system := connect("monitor", monitor)
	defer system.Close()
	events, err := system.SubscribeSync("$SYS.SERVER.*.STATSZ")
	must(err)
	must(system.Flush())
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
	_, err = js.CreateStream(ready, regionalowner.StreamConfig())
	must(err)
	loseQuorum := func() {
		for _, broker := range brokers[1:] {
			broker.Shutdown()
			broker.WaitForShutdown()
		}
	}
	cleanup := func() {
		admin.Close()
		orch.Close()
		for _, broker := range brokers {
			broker.Shutdown()
			broker.WaitForShutdown()
		}
	}
	return js, untrusted, loseQuorum, cleanup
}

func ownerEpochCase(ctx context.Context, work, region, managerState, foreignState string) {
	js, untrusted, loseQuorum, cleanup := ownerStoreCluster(ctx, filepath.Join(work, "owner-store"))
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
	store, err := regionalowner.Open(ctx, js, region, authorityKey, authenticate)
	must(err)
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
	apply := func(ctx context.Context, req regionalowner.Request, key ed25519.PrivateKey, signer string) (regionalowner.Snapshot, error) {
		wire, err := regionalowner.RequestMessage(req)
		must(err)
		proof := regionalowner.Proof{SessionSignature: ed25519.Sign(key, wire)}
		if signer != "" {
			proof.ManagerChain, proof.ManagerSignature, err = swarmruntime.SignRegional(signer, wire)
			must(err)
		}
		return store.Apply(ctx, req, proof)
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
	require(renewed.Revision > lease.Revision, "the live owner did not renew")
	publish := renew
	publish.Operation, publish.Sequence = regionalowner.Publish, 3
	publish.Digest = sha256.Sum256([]byte("regional owner observation"))
	published, err := apply(ctx, publish, old, "")
	must(err)
	require(published.Lease.Digest == publish.Digest && published.Revision > renewed.Revision, "valid publication did not reach quorum")

	revoked := view
	revoked.Epoch++
	revoked.Managers = nil
	reassigned, err := store.InstallMembership(ctx, revoked, signView(revoked, authority))
	must(err)
	require(reassigned.Lease.Node == "" && reassigned.Lease.Digest == ([32]byte{}) && reassigned.Revision > published.Revision,
		"membership epoch transition retained previous owner evidence")
	renew.Sequence, publish.Sequence = 4, 4
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
	committed, err := apply(ctx, valid, successor, "")
	must(err)
	require(committed.Lease.Digest == valid.Digest, "successor could not publish")
	loseQuorum()
	quorum, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	valid.Sequence++
	_, err = apply(quorum, valid, successor, "")
	require(errors.Is(err, regionalowner.ErrQuorum), fmt.Sprintf("publication without quorum did not fail closed: %v", err))
	logStep("the current owner cannot publish after two of the three store replicas stop")
}
