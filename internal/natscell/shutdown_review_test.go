package natscell

import "testing"

// A step-down clears the local leader before a successor exists; the
// handoff wait must keep waiting through that leaderless interval.
func TestSuccessorsElectedWaitsThroughLeaderlessGroups(t *testing.T) {
	stream := ledGroup{account: "A", stream: "S"}
	consumer := ledGroup{account: "A", stream: "S", consumer: "C"}
	led := []ledGroup{stream, consumer}
	cases := []struct {
		name    string
		leaders map[ledGroup]string
		want    bool
	}{
		{"observation failed", nil, false},
		{"leaderless after step-down", map[ledGroup]string{stream: "", consumer: "b"}, false},
		{"still self", map[ledGroup]string{stream: "a", consumer: "b"}, false},
		{"all handed off", map[ledGroup]string{stream: "c", consumer: "b"}, true},
		{"group deleted", map[ledGroup]string{consumer: "b"}, true},
	}
	for _, test := range cases {
		if got := successorsElected(test.leaders, led, "a"); got != test.want {
			t.Errorf("%s: successorsElected = %v, want %v", test.name, got, test.want)
		}
	}
}
