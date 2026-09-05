// Package preliminarycapture stages source-owned preliminary snapshots. Its
// owner request never authorizes fencing, a final cut, or candidate mutation.
package preliminarycapture
import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)


const MaximumBytes = 64 << 10
const domain = "TS-PRELIMINARY-CONTROL-CAPTURE-REQUEST-V1\x00"
const receiptDomain = "TS-PRELIMINARY-CONTROL-CAPTURE-RECEIPT-V1\x00"
type AccountInventory struct { Account string `json:"account"`; Streams []string `json:"streams"` }
type Account = AccountInventory
type Request struct {
 Version int `json:"version"`
 TransitionID string `json:"transitionId"`
 SourceNodeID string `json:"sourceNodeId"`
 InitialGrantSHA256 string `json:"initialGrantSha256"`
 StoreScopeSHA256 string `json:"storeScopeSha256"`
 ProfileSHA256 string `json:"profileSha256"`
 Accounts []AccountInventory `json:"accounts"`
 ControlEpoch uint64 `json:"controlEpoch"`
 IssuedAt time.Time `json:"issuedAt"`
 ExpiresAt time.Time `json:"expiresAt"`
}
type signedDocument struct { Payload json.RawMessage `json:"payload"`; Signature []byte `json:"signature"` }
type VerifiedRequest struct { Request Request; Digest string; OwnerKeyID string; Signed []byte; public []byte }
func token(s string) bool {
	_, e := hostmanifest.RequireToken(s, "identity", "preliminarycapture: invalid identity")
	return e == nil
}
func digest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func canonicalDecode(raw []byte, v any) error {
	if len(raw) == 0 || len(raw) > MaximumBytes {
		return errors.New("preliminarycapture: document exceeds bound")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(&struct{}{}) != io.EOF {
		return errors.New("preliminarycapture: malformed document")
	}
	encoded, e := json.Marshal(v)
	if e != nil || !bytes.Equal(raw, encoded) {
		return errors.New("preliminarycapture: noncanonical document")
	}
	return nil
}

func CanonicalRequest(r Request)([]byte,error) {
 if r.Version!=1 || !token(r.TransitionID) || !token(r.SourceNodeID) || !strings.HasPrefix(r.SourceNodeID,"gru-") || !digest(r.InitialGrantSHA256) || !digest(r.StoreScopeSHA256) || !digest(r.ProfileSHA256) || r.ControlEpoch==0 || r.IssuedAt.IsZero() || !r.ExpiresAt.After(r.IssuedAt) || r.ExpiresAt.Sub(r.IssuedAt)>24*time.Hour || len(r.Accounts)!=2 { return nil,errors.New("preliminarycapture: invalid finite source request") }
 seen:=map[string]bool{}
 for _,a:=range r.Accounts {
 if !name(a.Account) || seen[a.Account] || len(a.Streams)==0 || len(a.Streams)>128 {return nil,errors.New("preliminarycapture: invalid account inventory")};seen[a.Account]=true
 for i,s:=range a.Streams {if !name(s) || (i>0 && s<=a.Streams[i-1]) {return nil,errors.New("preliminarycapture: streams must be uniquely sorted")}}
 }
 raw,err:=json.Marshal(r);if err!=nil || len(raw)>MaximumBytes {return nil,errors.New("preliminarycapture: request exceeds bound")};return raw,nil
}
func name(value string)bool {if len(value)==0 || len(value)>255{return false};for _,r:=range value {if !(r>='A'&&r<='Z'||r>='a'&&r<='z'||r>='0'&&r<='9'||r=='_'||r=='-'){return false}};return true}
func SignRequest(s *security.CommandSignatureSigner, g Request) ([]byte, error) {
	if s == nil {
		return nil, errors.New("preliminarycapture: owner signer required")
	}
	raw, e := CanonicalRequest(g)
	if e != nil {
		return nil, e
	}
	sig, e := s.SignCanonicalMaterial(append([]byte(domain), raw...))
	if e != nil {
		return nil, e
	}
	return json.Marshal(signedDocument{raw, sig.Bytes()})
}
func VerifyRequest(public, signed []byte) (VerifiedRequest, error) {
	fail := func() (VerifiedRequest, error) {
		return VerifiedRequest{}, errors.New("preliminarycapture: owner signature or grant refused")
	}
	block, rest := pem.Decode(public)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return fail()
	}
	parsed, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		return fail()
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return fail()
	}
	var doc signedDocument
	if canonicalDecode(signed, &doc) != nil {
		return fail()
	}
	var g Request
	if canonicalDecode(doc.Payload, &g) != nil {
		return fail()
	}
	canonical, e := CanonicalRequest(g)
	if e != nil || !bytes.Equal(canonical, doc.Payload) {
		return fail()
	}
	signature, ok := protocol.OpaqueSignatureTryCopyFrom(doc.Signature)
	if !ok {
		return fail()
	}
	id, _, sig, ok := security.DecodeCommandSignature(signature)
	owner := sha256.Sum256(block.Bytes)
	keyID := hex.EncodeToString(owner[:])
	hash := sha256.Sum256(append([]byte(domain), doc.Payload...))
	if !ok || id != keyID || !ecdsa.VerifyASN1(key, hash[:], sig) {
		return fail()
	}
	sum := sha256.Sum256(signed)
	return VerifiedRequest{Request:g, Digest:hex.EncodeToString(sum[:]), OwnerKeyID:keyID,Signed:append([]byte(nil),signed...),public:append([]byte(nil),public...)}, nil
}

func (v VerifiedRequest) Check(now time.Time)error {
 verified,err:=VerifyRequest(v.public,v.Signed)
 a,_:=json.Marshal(v.Request);b,_:=json.Marshal(verified.Request)
 if err!=nil || v.Digest!=verified.Digest || v.OwnerKeyID!=verified.OwnerKeyID || !bytes.Equal(a,b) || now.Before(v.Request.IssuedAt) || !now.Before(v.Request.ExpiresAt) {return errors.New("preliminarycapture: request expired or verification scope changed")};return nil
}
type Object struct { Account string `json:"account"`; Stream string `json:"stream"`; Key string `json:"key"`; SHA256 string `json:"sha256"`; Size int64 `json:"size"`; CreatedAt time.Time `json:"createdAt"` }
type Receipt struct { Version int `json:"version"`; Preliminary bool `json:"preliminary"`; TransitionID string `json:"transitionId"`; RequestSHA256 string `json:"requestSha256"`; SourceNodeID string `json:"sourceNodeId"`; ControlEpoch uint64 `json:"controlEpoch"`; CreatedAt time.Time `json:"createdAt"`; Objects []Object `json:"objects"` }
func canonicalReceipt(r Receipt)([]byte,error) {
 if r.Version!=1 || !r.Preliminary || !token(r.TransitionID) || !digest(r.RequestSHA256) || !token(r.SourceNodeID) || !strings.HasPrefix(r.SourceNodeID,"gru-") || r.ControlEpoch==0 || r.CreatedAt.IsZero() || len(r.Objects)==0 || len(r.Objects)>256 {return nil,errors.New("preliminarycapture: invalid preliminary receipt")}
 seen:=map[string]bool{}
 for _,o:=range r.Objects {key,err:=ObjectKey(o.Account,o.Stream,r.ControlEpoch);if err!=nil || key!=o.Key || seen[key] || !digest(strings.TrimPrefix(o.SHA256,"sha256:")) || !strings.HasPrefix(o.SHA256,"sha256:") || o.Size<=0 || o.Size>1<<30 || o.CreatedAt.IsZero() || o.CreatedAt.After(r.CreatedAt){return nil,errors.New("preliminarycapture: invalid receipt artifact")};seen[key]=true}
 raw,err:=json.Marshal(r);if err!=nil || len(raw)>MaximumBytes{return nil,errors.New("preliminarycapture: receipt exceeds bound")};return raw,nil
}
func SignReceipt(s *security.CommandSignatureSigner,r Receipt)([]byte,error) {if s==nil{return nil,errors.New("preliminarycapture: source signer required")};raw,err:=canonicalReceipt(r);if err!=nil{return nil,err};sig,err:=s.SignCanonicalMaterial(append([]byte(receiptDomain),raw...));if err!=nil{return nil,err};signed,err:=json.Marshal(signedDocument{raw,sig.Bytes()});if len(signed)>MaximumBytes{return nil,errors.New("preliminarycapture: signed receipt exceeds bound")};return signed,err}
func VerifyReceipt(public,signed []byte)(Receipt,error) {
 var doc signedDocument;var r Receipt
 if canonicalDecode(signed,&doc)!=nil || canonicalDecode(doc.Payload,&r)!=nil{return Receipt{},errors.New("preliminarycapture: malformed source receipt")}
 raw,err:=canonicalReceipt(r);if err!=nil || !bytes.Equal(raw,doc.Payload){return Receipt{},errors.New("preliminarycapture: invalid source receipt")}
 block,rest:=pem.Decode(public);if block==nil || block.Type!="PUBLIC KEY" || len(bytes.TrimSpace(rest))!=0{return Receipt{},errors.New("preliminarycapture: source public key required")}
 parsed,err:=x509.ParsePKIXPublicKey(block.Bytes);if err!=nil{return Receipt{},err};key,ok:=parsed.(*ecdsa.PublicKey);if !ok || key.Curve!=elliptic.P256(){return Receipt{},errors.New("preliminarycapture: source P256 key required")}
 signature,ok:=protocol.OpaqueSignatureTryCopyFrom(doc.Signature);if !ok{return Receipt{},errors.New("preliminarycapture: source signature required")};id,_,sig,ok:=security.DecodeCommandSignature(signature);keyHash:=sha256.Sum256(block.Bytes);hash:=sha256.Sum256(append([]byte(receiptDomain),doc.Payload...));if !ok || id!=hex.EncodeToString(keyHash[:]) || !ecdsa.VerifyASN1(key,hash[:],sig){return Receipt{},errors.New("preliminarycapture: source signature refused")};return r,nil
}
