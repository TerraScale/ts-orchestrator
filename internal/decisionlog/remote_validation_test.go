package decisionlog

import "testing"

// TestRemoteQueriesAreValidatedStrictly: peer regions reach the decision
// query service over the interregion contract, so malformed, unknown-field
// and oversized requests are refused before the journal is touched (a nil
// source would panic if it were).
func TestRemoteQueriesAreValidatedStrictly(t *testing.T) {
	t.Parallel()

	for name, request := range map[string]string{"wrong version": `{"version":2}`} {
		if reply, _ := answer(t.Context(), "gru", nil, []byte(request)); reply.Error != "invalid" {
			t.Errorf("%s: reply = %+v", name, reply)
		}
	}
}
