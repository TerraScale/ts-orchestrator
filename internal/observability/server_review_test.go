package observability

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fixedSnapshot string

func (member fixedSnapshot) Snapshot(context.Context, bool) (MemberSnapshot, error) {
	return MemberSnapshot{Member: string(member)}, nil
}

type fixedCluster string

func (cell fixedCluster) Cluster(context.Context, bool) (ClusterSnapshot, error) {
	return ClusterSnapshot{Cell: string(cell)}, nil
}

func TestServerRemountsJSONViewsWithoutPanicking(t *testing.T) {
	t.Parallel()
	server, err := NewServer(Config{ListenAddress: "127.0.0.1:9464"}, ServerDeps{Registry: NewRegistry(false),
		Health: new(Health), Snapshots: fixedSnapshot("first"), Cluster: fixedCluster("first")})
	if err != nil {
		t.Fatal(err)
	}
	// A runtime that also late-mounts the same views must replace the
	// source, not register the pattern again (ServeMux would panic).
	server.HandleSnapshots(fixedSnapshot("second"))
	server.HandleCluster(fixedCluster("second"))
	get := func(path string, into any) {
		recorder := httptest.NewRecorder()
		// A tokenless listener only answers IP-literal or localhost Hosts;
		// httptest's default example.com would draw 421.
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Host = "127.0.0.1:9464"
		server.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s = %d", path, recorder.Code)
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), into); err != nil {
			t.Fatal(err)
		}
	}
	var member MemberSnapshot
	get("/v1/snapshot", &member)
	var cluster ClusterSnapshot
	get("/v1/cluster", &cluster)
	if member.Member != "second" || cluster.Cell != "second" {
		t.Fatalf("snapshot = %+v, cluster = %+v", member, cluster)
	}
}
