package natscell

import (
	"testing"

	"github.com/nats-io/nats-server/v2/server"
)

// The configured replication factor is authoritative, and the peer-count
// fallback follows the cluster info shape: a leaderless group lists every
// peer, this server included, so an R3 stream never reads as R4 while it is
// degraded (#127 12136).
func TestStreamViewReportsTheConfiguredReplicationFactor(t *testing.T) {
	two := []*server.PeerInfo{{Name: "b"}, {Name: "c"}}
	three := []*server.PeerInfo{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	for _, test := range []struct {
		name   string
		stream server.StreamDetail
		want   int
	}{
		{"configured leaderless", server.StreamDetail{Config: &server.StreamConfig{Replicas: 3},
			Cluster: &server.ClusterInfo{Replicas: three}}, 3},
		{"configured led", server.StreamDetail{Config: &server.StreamConfig{Replicas: 3},
			Cluster: &server.ClusterInfo{Leader: "a", Replicas: two}}, 3},
		{"fallback led", server.StreamDetail{Cluster: &server.ClusterInfo{Leader: "a", Replicas: two}}, 3},
		{"fallback leaderless", server.StreamDetail{Cluster: &server.ClusterInfo{Replicas: three}}, 3},
		{"standalone", server.StreamDetail{Cluster: &server.ClusterInfo{Leader: "a"}}, 1},
	} {
		if got := streamView(test.stream).Replicas; got != test.want {
			t.Errorf("%s: replicas = %d, want %d", test.name, got, test.want)
		}
	}
}
