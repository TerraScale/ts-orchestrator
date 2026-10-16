// Copyright 2018 The NATS Authors
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
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestClosedConnectionRingOverHTTP(t *testing.T) {
	const capacity = 10
	opts := DefaultOptions()
	opts.MaxClosedClients = capacity
	opts.HTTPHost, opts.HTTPPort = "127.0.0.1", -1
	opts.NoSystemAccount = true
	s := RunServer(opts)
	defer s.Shutdown()

	monitorURL := "http://" + s.MonitorAddr().String()
	hc := &http.Client{Timeout: time.Second}
	defer hc.CloseIdleConnections()
	readJSON := func(path string, result any) error {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, monitorURL+path, nil)
		if err != nil {
			return err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s returned %s", path, resp.Status)
		}
		return json.NewDecoder(resp.Body).Decode(result)
	}

	var ids []uint64
	for i := range 100 {
		name := fmt.Sprintf("closed-ring-%d", i+1)
		nc, err := nats.Connect(s.ClientURL(), nats.Name(name), nats.Timeout(time.Second), nats.NoReconnect())
		require_NoError(t, err)
		id, err := nc.GetClientID()
		nc.Close()
		require_NoError(t, err)
		ids = append(ids, id)

		checkFor(t, 2*time.Second, 5*time.Millisecond, func() error {
			var v Varz
			if err := readJSON("/varz", &v); err != nil {
				return err
			}
			if v.TotalConnections != uint64(len(ids)) || v.Connections != 0 {
				return fmt.Errorf("after closing %s: total=%d active=%d", name, v.TotalConnections, v.Connections)
			}
			var c Connz
			if err := readJSON("/connz?state=closed&sort=cid&limit=10", &c); err != nil {
				return err
			}
			want := ids[max(0, len(ids)-capacity):]
			if c.Total != len(want) || c.NumConns != len(want) || len(c.Conns) != len(want) {
				return fmt.Errorf("after closing %s: closed total=%d page=%d entries=%d, want %d", name, c.Total, c.NumConns, len(c.Conns), len(want))
			}
			for j, ci := range c.Conns {
				wantName := fmt.Sprintf("closed-ring-%d", len(ids)-len(want)+j+1)
				if ci.Cid != want[j] || ci.Name != wantName || ci.Stop == nil {
					return fmt.Errorf("closed[%d]=%d/%q stopped=%v, want %d/%q", j, ci.Cid, ci.Name, ci.Stop != nil, want[j], wantName)
				}
			}
			return nil
		})
	}
}
