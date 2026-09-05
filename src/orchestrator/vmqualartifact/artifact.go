// Package vmqualartifact serves explicitly pinned qualification release bytes.
package vmqualartifact

import (
 "crypto/ed25519"
 "crypto/rand"
 "crypto/tls"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/pem"
 "errors"
 "math/big"
 "net/http"
 "strconv"
 "time"
)

func GenerateCertificate(hostname string, now time.Time) (tls.Certificate, []byte, error) {
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	defer clear(caPrivate)
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	failed := true
	defer func() {
		if failed {
			clear(serverPrivate)
		}
	}()
	caSerial, err := certificateSerial()
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serverSerial, err := certificateSerial()
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber: caSerial, Subject: pkix.Name{CommonName: "TerraScale VM qualification artifact CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: serverSerial, Subject: pkix.Name{CommonName: hostname},
		DNSNames: []string{hostname}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(12 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, serverPublic, caPrivate)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(serverDER)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if len(caPEM) == 0 {
		return tls.Certificate{}, nil, errors.New("vmqual: encode artifact CA certificate")
	}
	failed = false
	return tls.Certificate{Certificate: [][]byte{serverDER, caDER}, PrivateKey: serverPrivate, Leaf: leaf}, caPEM, nil
}

func certificateSerial() (*big.Int, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	value[0] &= 0x7f
	value[0] |= 0x01
	return new(big.Int).SetBytes(value), nil
}

func ReleasePaths(component, version string) (string, string) {
	artifact := "/releases/" + component + "/" + version + "/" + component
	return artifact, artifact + ".sig"
}

func Handler(hostname string, port uint16, resources map[string][]byte) http.Handler {
	wantHost := hostname + ":" + strconv.Itoa(int(port))
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.TLS == nil || request.Method != http.MethodGet || request.Host != wantHost ||
			request.URL.RawQuery != "" || request.URL.Fragment != "" || request.ContentLength > 0 ||
			request.URL.EscapedPath() != request.URL.Path {
			http.Error(response, "not found", http.StatusNotFound)
			return
		}
		data, ok := resources[request.URL.Path]
		if !ok {
			http.Error(response, "not found", http.StatusNotFound)
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "application/octet-stream")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("Content-Length", strconv.Itoa(len(data)))
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(data)
	})
}

