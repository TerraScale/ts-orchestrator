package finalcapture

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
)

type privateBroker struct {
	once        sync.Once
	server      *natsserver.Server
	connections map[string]*nats.Conn
	keys        []nkeys.KeyPair
}

func (b *privateBroker) close() {
	if b == nil {
		return
	}
	b.once.Do(func() {
		for _, c := range b.connections {
			c.Close()
		}
		if b.server != nil {
			b.server.Shutdown()
			b.server.WaitForShutdown()
		}
		for _, k := range b.keys {
			k.Wipe()
		}
	})
}

func startBroker(ctx context.Context, v controltransition.VerifiedPlan) (_ *privateBroker, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	p, err := v.Plan()
	if err != nil {
		return nil, err
	}
	// Disk namespace admission is independent of API enumeration: an unknown
	// account must not disappear merely because no user was configured for it.
	entries, err := os.ReadDir(filepath.Join(p.Source.CaptureDir, "jetstream"))
	if err != nil {
		return nil, err
	}
	accounts := map[string]bool{}
	for _, a := range p.Accounts {
		accounts[a.SourceName] = true
	}
	for _, entry := range entries {
		if !accounts[entry.Name()] || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("finalcapture: copied store contains an unadmitted account")
		}
	}
	if len(entries) != len(accounts) {
		return nil, errors.New("finalcapture: copied store account missing")
	}
	options := &natsserver.Options{DontListen: true, NoSigs: true, NoLog: true, JetStream: true, StoreDir: p.Source.CaptureDir, ServerName: p.Source.ServerName + "-capture", JetStreamMaxStore: p.Limits.MaxStoreBytes, JetStreamMaxMemory: 1 << 20, MaxPayload: 2 << 20}
	b := &privateBroker{connections: map[string]*nats.Conn{}}
	defer func() {
		if err != nil {
			b.close()
		}
	}()
	for _, a := range p.Accounts {
		account := natsserver.NewAccount(a.SourceName)
		options.Accounts = append(options.Accounts, account)
		key, e := nkeys.CreateUser()
		if e != nil {
			return nil, e
		}
		b.keys = append(b.keys, key)
		public, e := key.PublicKey()
		if e != nil {
			return nil, e
		}
		publish := []string{"$JS.API.STREAM.NAMES"}
		for _, s := range a.Streams {
			publish = append(publish, "$JS.API.STREAM.INFO."+s.Name, "$JS.API.STREAM.SNAPSHOT."+s.Name, "$JS.API.STREAM.MSG.GET."+s.Name, "$JS.API.CONSUMER.NAMES."+s.Name, "$JS.API.CONSUMER.INFO."+s.Name+".*", "$JS.SNAPSHOT.ACK."+s.Name+".>")
		}
		options.Nkeys = append(options.Nkeys, &natsserver.NkeyUser{Nkey: public, Account: account, Permissions: &natsserver.Permissions{Publish: &natsserver.SubjectPermission{Allow: publish}, Subscribe: &natsserver.SubjectPermission{Allow: []string{"_INBOX.>"}}}})
	}
	b.server, err = natsserver.NewServer(options)
	if err != nil {
		return nil, err
	}
	b.server.Start()
	if !b.server.ReadyForConnections(5 * time.Second) {
		return nil, errors.New("finalcapture: private capture broker unavailable")
	}
	for i, a := range p.Accounts {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		account, e := b.server.LookupAccount(a.SourceName)
		if e != nil {
			return nil, e
		}
		if e = account.EnableJetStream(nil, nil); e != nil {
			return nil, e
		}
		public, _ := b.keys[i].PublicKey()
		nc, e := nats.Connect("", nats.InProcessServer(b.server), nats.Nkey(public, b.keys[i].Sign), nats.NoReconnect())
		if e != nil {
			return nil, e
		}
		b.connections[a.SourceName] = nc
	}
	return b, nil
}
