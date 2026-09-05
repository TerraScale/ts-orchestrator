package candidatesync

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
)

type privateBroker struct {
	once        sync.Once
	server      *natsserver.Server
	connections map[string]*nats.Conn
}

func (b *privateBroker) close() {
	if b == nil {
		return
	}
	b.once.Do(func() {
		for _, c := range b.connections {
			c.Close()
		}
		b.server.Shutdown()
		b.server.WaitForShutdown()
	})
}
func startBroker(ctx context.Context, path string, maximum int64, objects []preliminarytransfer.ObjectMapping) (result *privateBroker, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	accounts := map[string]*natsserver.Account{}
	options := &natsserver.Options{DontListen: true, NoSigs: true, NoLog: true, JetStream: true, StoreDir: filepath.Join(path, "data"), JetStreamMaxStore: maximum, JetStreamMaxMemory: 1 << 20}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	password := hex.EncodeToString(nonce[:])
	for _, o := range objects {
		if accounts[o.Account] != nil {
			continue
		}
		a := natsserver.NewAccount(o.Account)
		accounts[o.Account] = a
		options.Accounts = append(options.Accounts, a)
		options.Users = append(options.Users, &natsserver.User{Username: o.Account, Password: password, Account: a})
	}
	if err = knownBrokerLayout(path, accounts); err != nil {
		return nil, err
	}
	s, err := natsserver.NewServer(options)
	if err != nil {
		return nil, err
	}
	b := &privateBroker{server: s, connections: map[string]*nats.Conn{}}
	defer func() {
		if err != nil {
			b.close()
		}
	}()
	s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		return nil, errors.New("candidatesync: private broker unavailable")
	}
	for name := range accounts {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		a, e := s.LookupAccount(name)
		if e != nil {
			return nil, e
		}
		if e = a.EnableJetStream(nil, nil); e != nil {
			return nil, e
		}
		nc, e := nats.Connect("", nats.InProcessServer(s), nats.UserInfo(name, password), nats.NoReconnect())
		if e != nil {
			return nil, e
		}
		b.connections[name] = nc
		js, e := jetstream.New(nc)
		if e != nil {
			return nil, e
		}
		allowed := map[string]bool{}
		for _, o := range objects {
			if o.Account == name {
				allowed[o.Stream] = true
			}
		}
		names := js.StreamNames(ctx)
		for stream := range names.Name() {
			if !allowed[stream] {
				return nil, errors.New("candidatesync: unknown persistent target stream")
			}
		}
		if e = names.Err(); e != nil {
			return nil, e
		}
	}
	return b, nil
}

func knownBrokerLayout(path string, accounts map[string]*natsserver.Account) error {
	levels := []struct {
		path    string
		allowed map[string]bool
	}{
		{path, map[string]bool{"scope.json": true, "data": true}},
		{filepath.Join(path, "data"), map[string]bool{"jetstream": true}},
	}
	allowed := map[string]bool{}
	for name := range accounts {
		allowed[name] = true
	}
	levels = append(levels, struct {
		path    string
		allowed map[string]bool
	}{filepath.Join(path, "data", "jetstream"), allowed})
	for _, level := range levels {
		entries, e := os.ReadDir(level.path)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		for _, entry := range entries {
			if !level.allowed[entry.Name()] {
				return errors.New("candidatesync: unknown persistent broker account or layout")
			}
		}
	}
	return nil
}
