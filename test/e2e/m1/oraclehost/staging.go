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
	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/TerraScale/ts-orchestrator/internal/releasegate"
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
	if strings.HasSuffix(tag, releasegate.WithdrawalSuffix) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	now := time.Now().UTC().Add(-24 * time.Hour)
	record, err := json.Marshal(releasegate.StagingRecord{Binaries: s.github.stagingBinaries(tag), BakeFor: pullrelease.DefaultBakeFor, Region: fleet.Embedded().Staging.Label, Tag: tag,
		Done: now.Add(-2 * pullrelease.DefaultBakeFor), Baked: now.Add(-pullrelease.DefaultBakeFor), Signed: now})
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
	writeJSON(w, http.StatusOK, releasegate.SignedRecord{Record: record, Signature: signature})
}

func stagingTag(host, path string) (string, bool) {
	tag, ok := strings.CutPrefix(path, stagingGate.Path)
	return tag, ok && host == stagingGate.Host && tag != ""
}

func (g *GitHub) stagingBinaries(tag string) map[string]string {
	g.mu.Lock()
	defer g.mu.Unlock()
	binaries := map[string]string{}
	for _, releases := range [][]map[string]any{g.published, g.recorded} {
		for _, release := range releases {
			if release["tag_name"] != tag {
				continue
			}
			assets, _ := release["assets"].([]any)
			for _, raw := range assets {
				asset, _ := raw.(map[string]any)
				name, _ := asset["name"].(string)
				digest, _ := asset["digest"].(string)
				if arch, ok := strings.CutPrefix(name, releaseattest.AssetPrefix); ok {
					binaries[arch] = strings.TrimPrefix(digest, "sha256:")
				}
			}
			return binaries
		}
	}
	return binaries
}
