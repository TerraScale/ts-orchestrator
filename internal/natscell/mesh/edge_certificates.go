package mesh

import (
	"context"

	"github.com/nats-io/nats.go"
)

func (n *Node) EdgeCertificateStore() (*nats.Conn, []byte, error) {
	return n.conn, n.cfg.ca.key.Seed(), nil
}

func (n *Node) EdgeCertificateNodes() (string, []string, error) {
	n.peers.mu.Lock()
	defer n.peers.mu.Unlock()
	nodes := []string{n.cfg.server}
	regions := map[string]bool{n.cfg.region: true}
	for region := range n.cfg.seeds {
		regions[region] = true
	}
	for region := range n.peers.admitted {
		regions[region] = true
	}
	for region := range regions {
		if at, ok := n.peers.admitted[region]; ok {
			nodes = append(nodes, at.node)
		} else {
			nodes = append(nodes, "ts-"+region+"-1")
		}
		for _, at := range n.peers.workers[region] {
			nodes = append(nodes, at.node)
		}
	}
	for _, at := range n.joinedWorkers() {
		nodes = append(nodes, at.Node)
	}
	return n.cfg.server, nodes, nil
}

func EdgeCertificateClient(ctx context.Context, state string) (*nats.Conn, []byte, error) {
	secret, err := loadSecret(ctx, secretName, "ts-orch mesh CA seed")
	if err != nil {
		return nil, nil, err
	}
	ca, err := DeriveCA(secret)
	clear(secret)
	if err != nil {
		return nil, nil, err
	}
	conn, err := Connect(state)
	if err != nil {
		return nil, nil, err
	}
	return conn, ca.key.Seed(), nil
}
