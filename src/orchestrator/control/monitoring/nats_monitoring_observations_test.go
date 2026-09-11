package monitoring

import "testing"

// Two streams of one class must merge into a single gauge entry, and a
// hostile counter value must drop its entry instead of killing the process.
func TestJetStreamDetailMergesSameClassAndDropsHostileCounters(t *testing.T) {
	detail := natsMonitoringParsers{}.JetStreamDetail(`{"data":{"stream_detail":[
		{"name":"KV_ORCH_DELIVERY_GRU","state":{"messages":10,"bytes":100}},
		{"name":"KV_ORCH_DELIVERY_SFO","state":{"messages":5,"bytes":50}},
		{"name":"KV_ORCH_DELIVERY_BAD","state":{"messages":-1,"bytes":-1}}
	]}}`)
	if detail == nil {
		t.Fatal("detail unavailable")
	}
	if len(detail.Streams) != 1 {
		t.Fatalf("same-class streams were not merged: %+v", detail.Streams)
	}
	state := detail.Streams[0]
	if state.Streams != 2 || state.Messages != 15 || state.Bytes != 150 {
		t.Fatalf("merged stream state = %+v", state)
	}
}
