package rootoci

import "testing"

func TestAuthorityBindingRejectsUnadmittedOrRootOnlyIdentity(t *testing.T) {
	for _, call := range []Call{
		{},
		{state: &callState{root: true, sessionBinding: "root-call-nonce"}},
		{state: &callState{sessionBinding: "caller-asserted-without-kernel-witness"}},
		{state: &callState{witness: &ProcessWitness{}, sessionBinding: "no-real-authorizer"}},
	} {
		if binding, cap, err := call.AuthorityBindingSHA256(t.Context()); err == nil || binding != "" || !cap.IsZero() {
			t.Fatal("root-only, unadmitted or caller-built data became a durable original caller identity")
		}
	}
}

func TestAuthorityBootIDRequiresCanonicalKernelUUID(t *testing.T) {
	if !validAuthorityBootID("b7043f01-b0ab-44c1-8ec6-6335bb312078") {
		t.Fatal("rejected canonical kernel boot identity")
	}
	for _, value := range []string{"", "root-call-nonce", "b7043f01-b0ab-44c1-8ec6-6335bb312078\n", "b7043f01_b0ab-44c1-8ec6-6335bb312078", "g7043f01-b0ab-44c1-8ec6-6335bb312078"} {
		if validAuthorityBootID(value) {
			t.Fatal("accepted malformed kernel boot identity")
		}
	}
}
