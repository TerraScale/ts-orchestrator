package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type authority struct {
	mu         sync.Mutex
	base       string
	certID     string
	name       string
	key        *ecdsa.PublicKey
	window     map[string]any
	retryAfter string
	orders     map[string]string
	queries    int
	newOrders  int
	nonces     map[string]bool
	nonce      int
}

func authorityCertificateID(cert *x509.Certificate) (string, error) {
	var tbs, field asn1.RawValue
	if _, err := asn1.Unmarshal(cert.RawTBSCertificate, &tbs); err != nil {
		return "", err
	}
	rest, err := asn1.Unmarshal(tbs.Bytes, &field)
	if err != nil {
		return "", err
	}
	if field.Class == asn1.ClassContextSpecific && field.Tag == 0 {
		if _, err := asn1.Unmarshal(rest, &field); err != nil {
			return "", err
		}
	}
	if field.Tag != asn1.TagInteger {
		return "", fmt.Errorf("certificate serial is not an INTEGER")
	}
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 35}) {
			var aki struct {
				Identifier []byte `asn1:"optional,tag:0"`
			}
			if _, err := asn1.Unmarshal(extension.Value, &aki); err != nil {
				return "", err
			}
			return base64.RawURLEncoding.EncodeToString(aki.Identifier) + "." + base64.RawURLEncoding.EncodeToString(field.Bytes), nil
		}
	}
	return "", fmt.Errorf("certificate has no AKI extension")
}

func (a *authority) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nonce++
	nonce := base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(a.nonce)))
	a.nonces[nonce] = true
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Content-Type", "application/json")
	var envelope struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	var payload struct {
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
		Replaces string `json:"replaces"`
	}
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			http.Error(w, "JWS", http.StatusBadRequest)
			return
		}
		protected, err := base64.RawURLEncoding.DecodeString(envelope.Protected)
		var header struct {
			Algorithm string `json:"alg"`
			Account   string `json:"kid"`
			Nonce     string `json:"nonce"`
			URL       string `json:"url"`
		}
		if err != nil || json.Unmarshal(protected, &header) != nil || header.Algorithm != "ES256" || header.Account != a.base+"/account/1" || header.URL != a.base+r.URL.Path || !a.nonces[header.Nonce] {
			http.Error(w, "protected JWS", http.StatusBadRequest)
			return
		}
		delete(a.nonces, header.Nonce)
		signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
		digest := sha256.Sum256([]byte(envelope.Protected + "." + envelope.Payload))
		if err != nil || len(signature) != 64 || !ecdsa.Verify(a.key, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
			http.Error(w, "signature", http.StatusBadRequest)
			return
		}
		body, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
		if err != nil || len(body) > 0 && json.Unmarshal(body, &payload) != nil {
			http.Error(w, "payload", http.StatusBadRequest)
			return
		}
	}
	switch {
	case r.URL.Path == "/directory" || r.URL.Path == "/directory-no-ari":
		directory := map[string]string{"newNonce": a.base + "/nonce", "newAccount": a.base + "/account", "newOrder": a.base + "/new-order"}
		if r.URL.Path == "/directory" {
			directory["renewalInfo"] = a.base + "/renewal-info/"
		}
		_ = json.NewEncoder(w).Encode(directory)
	case r.URL.Path == "/nonce":
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(r.URL.Path, "/renewal-info/"):
		a.queries++
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || r.Header.Get("Accept") != "application/json" || strings.TrimPrefix(r.URL.Path, "/renewal-info/") != a.certID {
			http.Error(w, "renewal identifier or request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Retry-After", a.retryAfter)
		_ = json.NewEncoder(w).Encode(a.window)
	case r.URL.Path == "/new-order":
		a.newOrders++
		if r.Method != http.MethodPost || len(payload.Identifiers) != 1 || payload.Identifiers[0].Type != "dns" || payload.Identifiers[0].Value != a.name {
			http.Error(w, "identifiers", http.StatusBadRequest)
			return
		}
		if payload.Replaces != "" {
			if payload.Replaces != a.certID {
				a.problem(w, http.StatusBadRequest, "malformed", "unknown replacement certificate")
				return
			}
			for _, replaces := range a.orders {
				if replaces == a.certID {
					a.problem(w, http.StatusConflict, "alreadyReplaced", "replacement certificate already has an order")
					return
				}
			}
		}
		id := strconv.Itoa(len(a.orders) + 1)
		a.orders[id] = payload.Replaces
		w.Header().Set("Location", a.base+"/order/"+id)
		w.WriteHeader(http.StatusCreated)
		a.writeOrder(w, id)
	case strings.HasPrefix(r.URL.Path, "/order/"):
		id := strings.TrimPrefix(r.URL.Path, "/order/")
		if _, ok := a.orders[id]; !ok {
			http.NotFound(w, r)
			return
		}
		a.writeOrder(w, id)
	default:
		http.NotFound(w, r)
	}
}

func (a *authority) writeOrder(w http.ResponseWriter, id string) {
	order := map[string]any{"status": "ready", "identifiers": []map[string]string{{"type": "dns", "value": a.name}}, "authorizations": []string{}, "finalize": a.base + "/finalize/" + id}
	if a.orders[id] != "" {
		order["replaces"] = a.orders[id]
	}
	_ = json.NewEncoder(w).Encode(order)
}

func (a *authority) problem(w http.ResponseWriter, status int, kind, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "urn:ietf:params:acme:error:" + kind, "detail": detail, "status": status})
}

func (a *authority) renewalResponse(window map[string]any, retryAfter string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.window, a.retryAfter = window, retryAfter
}

func renewalWindow(start, end time.Time) map[string]any {
	return map[string]any{"suggestedWindow": map[string]any{"start": start, "end": end}, "explanationURL": "https://ca.e2e.test/explanation"}
}
