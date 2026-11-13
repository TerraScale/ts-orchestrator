package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

type certificateObservation struct {
	autocert.Cache
	edge *Edge
}

func (c certificateObservation) Put(ctx context.Context, key string, data []byte) error {
	err := c.Cache.Put(ctx, key, data)
	if err != nil {
		return err
	}
	if strings.HasSuffix(key, "+token") || strings.HasSuffix(key, "+http-01") || strings.HasPrefix(key, "acme_account") {
		return nil
	}
	public := []byte{}
	remaining := data
	for len(remaining) > 0 {
		block, next := pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			public = append(public, pem.EncodeToMemory(block)...)
		}
		remaining = next
	}
	if len(public) > 0 {
		cert, err := tls.X509KeyPair(public, data)
		if err == nil {
			c.edge.rememberCertificate(strings.TrimSuffix(key, "+rsa"), &cert)
		}
	}
	return nil
}

func (e *Edge) rememberCertificate(name string, cert *tls.Certificate) {
	if len(cert.Certificate) == 0 {
		return
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err == nil {
		e.held.Store(strings.ToLower(name)+"/"+leaf.PublicKeyAlgorithm.String(), cert)
	}
}
