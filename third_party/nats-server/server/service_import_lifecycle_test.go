// Copyright 2026 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"errors"
	"fmt"
	"slices"
	"testing"
)

func TestAccountServiceImportSubscriptionLifecycle(t *testing.T) {
	setup := func(t *testing.T) (*Account, *Account) {
		t.Helper()
		s, err := NewServer(&Options{Port: -1})
		require_NoError(t, err)
		t.Cleanup(s.Shutdown)
		a, dest := NewAccount("importer"), NewAccount("exporter")
		s.registerAccount(a)
		s.registerAccount(dest)
		t.Cleanup(a.removeAllServiceImportSubs)
		return a, dest
	}
	assertCurrent := func(t *testing.T, a *Account, current *serviceImportSubscription) {
		t.Helper()
		a.mu.RLock()
		client, owner, sid, count := a.ic, current.si.serviceSub, string(current.si.sid), len(a.serviceSubs)
		a.mu.RUnlock()
		require_Equal(t, client, current.client)
		require_Equal(t, owner, current)
		require_Equal(t, sid, string(current.sid))
		require_Equal(t, count, 1)
		matches := a.sl.Match("svc")
		require_Equal(t, len(matches.psubs), 1)
		require_Equal(t, matches.psubs[0], current.sub)
		current.client.mu.Lock()
		registered, closed := current.client.subs[string(current.sid)], current.sub.isClosed()
		current.client.mu.Unlock()
		require_Equal(t, registered, current.sub)
		require_False(t, closed)
	}
	assertRetired := func(t *testing.T, retired *serviceImportSubscription) {
		t.Helper()
		retired.client.mu.Lock()
		registered := retired.client.subs[string(retired.sid)]
		closed := true
		if retired.sub != nil {
			closed = retired.sub.isClosed()
		}
		retired.client.mu.Unlock()
		require_Equal(t, registered, (*subscription)(nil))
		require_True(t, closed)
	}

	t.Run("hidden old import and replacement owner", func(t *testing.T) {
		a, dest := setup(t)
		si, err := a.addServiceImport(dest, "svc", "svc", nil)
		require_NoError(t, err)
		old := si.serviceSub

		// Stop refresh after it hides its old import, before old-owner cleanup.
		a.mu.Lock()
		delete(a.imports.services, "svc")
		si.sid, si.serviceSub = nil, nil
		a.mu.Unlock()
		a.removeAllServiceImportSubs()
		assertRetired(t, old)
		require_Equal(t, len(a.sl.Match("svc").psubs), 0)

		si, err = a.addServiceImport(dest, "svc", "svc", nil)
		require_NoError(t, err)
		current := si.serviceSub
		require_True(t, current.client != old.client)
		// Refresh's delayed cleanup is owner-directed and idempotent.
		a.removeServiceImportSub(old)
		assertCurrent(t, a, current)
	})

	t.Run("retirement cancels a reserved insertion", func(t *testing.T) {
		a, dest := setup(t)
		si := &serviceImport{acc: dest, from: "svc", to: "svc"}
		a.imports.services = map[string][]*serviceImport{"svc": {si}}
		// Stop the real registration path between reservation and insertion.
		old, err := a.reserveServiceImportSub(si)
		require_NoError(t, err)
		require_True(t, old != nil)
		a.removeAllServiceImportSubs()
		require_NoError(t, a.addServiceImportSub(si))
		current := si.serviceSub
		require_True(t, current.client != old.client)

		// The old call still has C0/SID0 while the same import now owns C1/SID1.
		require_NoError(t, old.subscribe(a))
		a.removeServiceImportSub(old)
		assertRetired(t, old)
		assertCurrent(t, a, current)
	})

	t.Run("single removal and stale snapshot preserve successor", func(t *testing.T) {
		a, dest := setup(t)
		si := &serviceImport{acc: dest, from: "svc", to: "svc"}
		a.imports.services = map[string][]*serviceImport{"svc": {si}}
		old, err := a.reserveServiceImportSub(si)
		require_NoError(t, err)
		a.removeServiceImport(dest.Name, "svc")
		require_NoError(t, old.subscribe(a))
		// An addAll snapshot may still carry si after its map entry was removed.
		require_NoError(t, a.addServiceImportSub(si))
		require_Equal(t, len(a.sl.Match("svc").psubs), 0)
		replacement, err := a.addServiceImport(dest, "svc", "svc", nil)
		require_NoError(t, err)
		// A failed old registration must not remove a new import with the same key.
		a.removeServiceImportWithSubscription(dest.Name, "svc", old)
		assertRetired(t, old)
		assertCurrent(t, a, replacement.serviceSub)
	})

	t.Run("failed sublist insertion releases its reservation", func(t *testing.T) {
		a, dest := setup(t)
		// Exercise processSubEx's real Insert error after it has reserved a SID.
		si, err := a.addServiceImport(dest, "svc..invalid", "svc", nil)
		require_True(t, errors.Is(err, ErrMalformedSubject))
		require_Equal(t, si, (*serviceImport)(nil))
		a.mu.RLock()
		imports, pending, c := len(a.imports.services["svc..invalid"]), len(a.serviceSubs), a.ic
		a.mu.RUnlock()
		require_Equal(t, imports, 0)
		require_Equal(t, pending, 0)
		c.mu.Lock()
		registered := len(c.subs)
		c.mu.Unlock()
		require_Equal(t, registered, 0)
		require_Equal(t, a.sl.Count(), uint32(0))
	})

	t.Run("connected leaf interest balances across retirement", func(t *testing.T) {
		hub := runAccountProtocolServer(t, `
			accounts {
				importer { users: [{user: i, password: p}] }
				exporter { exports: [{service: svc}] }
			}
			leafnodes { listen: 127.0.0.1:-1 }
		`)
		hub.mu.RLock()
		address := hub.leafNodeListener.Addr().String()
		hub.mu.RUnlock()
		spoke := runAccountProtocolServer(t, fmt.Sprintf(`
			leafnodes { remotes: [{url: "nats://i:p@%s"}] }
		`, address))
		checkLeafNodeConnected(t, hub)
		checkLeafNodeConnected(t, spoke)
		a, err := hub.LookupAccount("importer")
		require_NoError(t, err)
		dest, err := hub.LookupAccount("exporter")
		require_NoError(t, err)
		t.Cleanup(a.removeAllServiceImportSubs)
		a.lmu.RLock()
		leafClients := slices.Clone(a.lleafs)
		a.lmu.RUnlock()
		require_Equal(t, len(leafClients), 1)
		interest := func() int32 {
			leafClients[0].mu.RLock()
			defer leafClients[0].mu.RUnlock()
			return leafClients[0].leaf.smap["svc"]
		}

		si, err := a.addServiceImport(dest, "svc", "svc", nil)
		require_NoError(t, err)
		old := si.serviceSub
		require_Equal(t, interest(), int32(1))
		a.removeAllServiceImportSubs()
		require_Equal(t, interest(), int32(0))
		require_NoError(t, old.subscribe(a))
		require_Equal(t, interest(), int32(0))
		require_NoError(t, a.addServiceImportSub(si))
		require_Equal(t, interest(), int32(1))
		a.removeServiceImportSub(old)
		require_Equal(t, interest(), int32(1))
		a.removeServiceImport(dest.Name, "svc")
		require_Equal(t, interest(), int32(0))
	})
}
