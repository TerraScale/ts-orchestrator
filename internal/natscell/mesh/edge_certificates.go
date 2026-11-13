package mesh

import "github.com/nats-io/nats.go"

func (n *Node) EdgeCertificateStore() (*nats.Conn, []byte, error) {
	return n.conn, n.cfg.ca.key.Seed(), nil
}
