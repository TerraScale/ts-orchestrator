package natscell

import (
	"strings"
	"testing"

	"github.com/nats-io/nkeys"
)

func TestMembershipCredentialsAreNarrowlyScoped(t *testing.T) {
	root := t.TempDir()
	systemKey, _ := nkeys.CreateAccount()
	systemID, _ := systemKey.PublicKey()
	otherKey, _ := nkeys.CreateAccount()
	otherID, _ := otherKey.PublicKey()
	credentials := func(name string, account nkeys.KeyPair, accountID string, publish []string, inbox bool) string {
		user, _ := nkeys.CreateUser()
		userID, _ := user.PublicKey()
		var subscribe []string
		if inbox {
			subscribe = []string{inboxPrefix("gru", userID) + ".>"}
		}
		return testJWTUserCredentialsWithKey(t, root, name, account, accountID, user, publish, subscribe)
	}
	scoped := []string{MembershipServerRemoveSubject, MembershipMetaStepdownSubject}
	if err := ValidateMembershipCredentials(credentials("ok.creds", systemKey, systemID, scoped, true),
		"gru", systemID); err != nil {
		t.Fatalf("scoped credentials rejected: %v", err)
	}
	for name, path := range map[string]string{
		"claim update": credentials("claims.creds", systemKey, systemID,
			[]string{"$SYS.REQ.ACCOUNT.X.CLAIMS.UPDATE"}, true),
		"extra publish": credentials("extra.creds", systemKey, systemID,
			append([]string{"$JS.API.>"}, scoped...), true),
		"remove only":   credentials("remove.creds", systemKey, systemID, scoped[:1], true),
		"no inbox":      credentials("noinbox.creds", systemKey, systemID, scoped, false),
		"other account": credentials("other.creds", otherKey, otherID, scoped, true),
	} {
		if err := ValidateMembershipCredentials(path, "gru", systemID); err == nil {
			t.Fatalf("%s credentials accepted", name)
		}
	}
}

func TestMembershipAPIErrorDecoding(t *testing.T) {
	if err := membershipAPIError("s", []byte(`{"type":"io.nats.jetstream.api.v1.meta_leader_stepdown_response","success":true}`)); err != nil {
		t.Fatal(err)
	}
	err := membershipAPIError("s", []byte(`{"error":{"code":400,"err_code":10118,"description":"peer not a member"}}`))
	if err == nil || !strings.Contains(err.Error(), "peer not a member") {
		t.Fatalf("api error = %v", err)
	}
	if err := membershipAPIError("s", []byte(`{}`)); err == nil {
		t.Fatal("missing success accepted")
	}
}
