package host

import (
	"crypto/sha256"

	"github.com/nats-io/nkeys"
)

func testNATSUserKey(node string) string {
	seed := sha256.Sum256([]byte("host-test-user:" + node))
	pair, err := nkeys.FromRawSeed(nkeys.PrefixByteUser, seed[:])
	if err != nil {
		panic(err)
	}
	defer pair.Wipe()
	public, err := pair.PublicKey()
	if err != nil {
		panic(err)
	}
	return public
}
