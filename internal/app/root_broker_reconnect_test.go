package app

import "testing"

func TestRootBrokerReconnectReplyRequiresAnActualCount(t *testing.T) {
	for _, wire := range []string{`{}`, `null`, `{"count":null}`, `{"count":-1}`, `{"count":1,"count":2}`, `{"count":1,"error":""}`, `{"count":1,"selector":"other-account"}`} {
		if _, err := decodeRootBrokerReconnectResponse([]byte(wire)); err == nil {
			t.Errorf("accepted %s", wire)
		}
	}
	for _, wire := range []string{`{"count":0}`, `{"count":2}`, `{"count":1,"error":"unavailable"}`} {
		if _, err := decodeRootBrokerReconnectResponse([]byte(wire)); err != nil {
			t.Errorf("rejected %s: %v", wire, err)
		}
	}
}
