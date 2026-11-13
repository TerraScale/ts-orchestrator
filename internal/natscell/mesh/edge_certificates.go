package mesh

import (
	"encoding/hex"
	"errors"

	"github.com/nats-io/nats.go"
)

func (n *Node) EdgeCertificateStore() (*nats.Conn, []byte, error) {
	key, err := hex.DecodeString(n.cfg.terrabaseToken)
	if err != nil || len(key) != 32 {
		return nil, nil, errors.New("edge: certificate encryption key unavailable")
	}
	return n.conn, key, nil
}
