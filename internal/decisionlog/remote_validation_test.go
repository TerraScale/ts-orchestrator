package decisionlog

import (
	"strings"
	"testing"
)

// TestRemoteQueriesAreValidatedStrictly: peer regions reach the decision
// query service over the interregion contract, so malformed, unknown-field
// and oversized requests are refused before the journal is touched (a nil
// source would panic if it were).
func TestRemoteQueriesAreValidatedStrictly(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("a", maxRemoteFilterBytes+1)
	many := `"` + strings.Repeat(`a","`, maxRemoteFilterValues) + `a"`
	for name, request := range map[string]string{
		"not json":         `{`,
		"wrong version":    `{"version":2}`,
		"unknown field":    `{"version":1,"admin":true}`,
		"trailing data":    `{"version":1}{"version":1}`,
		"long chain id":    `{"version":1,"chain_id":"` + long + `"}`,
		"control chars":    `{"version":1,"query":{"subject":"a\u0001b"}}`,
		"too many regions": `{"version":1,"query":{"regions":[` + many + `]}}`,
		"too many actors":  `{"version":1,"query":{"actors":[` + many + `]}}`,
		"negative limit":   `{"version":1,"query":{"limit":-1}}`,
	} {
		if reply, _ := answer(t.Context(), "gru", nil, []byte(request)); reply.Error != "invalid" {
			t.Errorf("%s: reply = %+v", name, reply)
		}
	}
}
