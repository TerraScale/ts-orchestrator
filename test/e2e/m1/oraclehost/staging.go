package oraclehost

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/pullrelease"
)

var stagingKey = func() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}()

var stagingGate = func() *url.URL {
	parsed, err := url.Parse(fleet.Embedded().Staging.GateURL(""))
	if err != nil {
		panic(err)
	}
	return parsed
}()

func StagingSigned(binary []byte) []byte {
	der, err := x509.MarshalPKIXPublicKey(&stagingKey.PublicKey)
	if err != nil {
		panic(err)
	}
	embedded, lane := []byte(fleet.Embedded().Staging.SignerPublicKey), []byte(base64.StdEncoding.EncodeToString(der))
	if len(embedded) != len(lane) {
		panic("the stand-in's staging signer key does not fit the embedded staging.signer_public_key")
	}
	return bytes.ReplaceAll(binary, embedded, lane)
}

func (s *standIn) staging(w http.ResponseWriter, tag string) {
	now := time.Now().UTC()
	record, err := json.Marshal(pullrelease.StagingRecord{Region: fleet.Embedded().Staging.Label, Tag: tag,
		Done: now.Add(-2 * pullrelease.DefaultBakeFor), Baked: now.Add(-pullrelease.DefaultBakeFor), Signed: now,
		Latency: pullrelease.LatencyVerdict{Verdict: pullrelease.LatencyPass, Run: "https://github.com/TerraScale/ts-orchestrator/actions/runs/1"}})
	if err != nil {
		serviceError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	digest := sha256.Sum256(record)
	signature, err := ecdsa.SignASN1(rand.Reader, stagingKey, digest[:])
	if err != nil {
		serviceError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pullrelease.SignedRecord{Record: record, Signature: signature})
}

func stagingTag(host, path string) (string, bool) {
	tag, ok := strings.CutPrefix(path, stagingGate.Path)
	return tag, ok && host == stagingGate.Host && tag != ""
}
