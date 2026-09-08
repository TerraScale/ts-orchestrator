package controltransition

import (
 "crypto/ecdsa"
 "crypto/sha256"
 "encoding/json/v2"
 "errors"
 "time"

 "terrascale.tech/orchestrator/src/orchestrator/protocol"
 "terrascale.tech/orchestrator/src/orchestrator/security"
)

const CutReceiptMaximumBytes = 16384
const cutReceiptDomain = "TS-CONTROL-STORAGE-SOURCE-COPY-V1\x00"

// CutReceipt proves a stopped source's byte-preserving working copy. It is
// deliberately not a snapshot or restoration receipt: capture must separately
// prove stream records and consumer checkpoints against this preserved store.
type CutReceipt struct {
 Version int `json:"version"`
 Phase string `json:"phase"`
 PlanSHA256 string `json:"planSha256"`
 NodeID string `json:"nodeId"`
 BootstrapGrantSHA256 string `json:"bootstrapGrantSha256"`
 StoreScopeSHA256 string `json:"storeScopeSha256"`
 StoreSHA256 string `json:"storeSha256"`
 CopySHA256 string `json:"copySha256"`
 SourceDevice uint64 `json:"sourceDevice"`
 SourceInode uint64 `json:"sourceInode"`
 Files int64 `json:"files"`
 Bytes int64 `json:"bytes"`
 StoppedAt time.Time `json:"stoppedAt"`
 CopiedAt time.Time `json:"copiedAt"`
}

func cutReceiptKey(v VerifiedPlan, r CutReceipt) (string,error) {
 p,err:=v.Plan(); if err!=nil { return "",err }
 if r.Version!=1 || r.Phase!="source-store-copied" || r.PlanSHA256!=v.Digest() || r.NodeID!=p.Source.NodeID || r.BootstrapGrantSHA256!=p.Source.BootstrapGrantSHA256 || r.StoreScopeSHA256!=p.Source.StoreScopeSHA256 || !validDigest(r.StoreSHA256) || r.CopySHA256!=r.StoreSHA256 || r.SourceInode==0 || r.Files<=0 || r.Files>p.Limits.MaxStoreFiles || r.Bytes<0 || r.Bytes>p.Limits.MaxStoreBytes || v.Check(r.StoppedAt)!=nil || v.Check(r.CopiedAt)!=nil || r.CopiedAt.Before(r.StoppedAt) { return "",errors.New("controltransition: invalid source copy receipt") }
 return p.Source.ReceiptPublicKeyPEM,nil
}

func SignCutReceipt(signer *security.CommandSignatureSigner,v VerifiedPlan,r CutReceipt)([]byte,error){
 public,err:=cutReceiptKey(v,r); if err!=nil{return nil,err}
 id,err:=publicKeyID([]byte(public)); if err!=nil || signer==nil || signer.PublicKeyID()!=id{return nil,errors.New("controltransition: wrong source copy signer")}
 raw,err:=json.Marshal(r); if err!=nil{return nil,err}
 sig,err:=signer.SignCanonicalMaterial(append([]byte(cutReceiptDomain),raw...)); if err!=nil{return nil,err}
 signed,err:=json.Marshal(signedPlan{Payload:raw,Signature:sig.Bytes()}); if err!=nil || len(signed)>CutReceiptMaximumBytes{return nil,errors.New("controltransition: source copy receipt exceeds bound")};return signed,nil
}

func VerifyCutReceipt(v VerifiedPlan,raw []byte)(CutReceipt,error){
 var r CutReceipt; var doc signedPlan
 bad:=errors.New("controltransition: source copy signature refused")
 if len(raw)>CutReceiptMaximumBytes || canonicalDecode(raw,&doc)!=nil || canonicalDecode(doc.Payload,&r)!=nil{return CutReceipt{},bad}
 public,err:=cutReceiptKey(v,r);if err!=nil{return CutReceipt{},err}
 key,owner,err:=publicKey([]byte(public));if err!=nil{return CutReceipt{},bad}
 signature,ok:=protocol.OpaqueSignatureTryCopyFrom(doc.Signature);if !ok{return CutReceipt{},bad}
 id,_,sig,ok:=security.DecodeCommandSignature(signature);hash:=sha256.Sum256(append([]byte(cutReceiptDomain),doc.Payload...))
 if !ok || id!=owner || !ecdsa.VerifyASN1(key,hash[:],sig){return CutReceipt{},bad};return r,nil
}
