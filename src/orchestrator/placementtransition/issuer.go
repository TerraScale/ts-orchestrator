package placementtransition

import (
 "context"
 "crypto/ed25519"
 "encoding/json/v2"
 "maps"
 "slices"

 "terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
)

type entry struct { RequestDigest string; Proof Signed }
type state struct { Operations map[string]entry; Heads map[string]string; Genesis map[string]string }
type transaction interface { TransactRevision(context.Context,bool,func(*state,uint64)error)error }
type Config struct {
 Authority authorityjournal.Config
 ProofKeyID string
 ProofKey ed25519.PrivateKey
 GenesisKeys map[string]ed25519.PublicKey
 // MemberKeys binds each exact old member identity to its receipt key.
 MemberKeys map[string]ed25519.PublicKey
}
type Issuer struct { journal transaction; keyID string; key ed25519.PrivateKey; epoch uint64; genesisKeys,memberKeys map[string]ed25519.PublicKey }
func emptyState()state{return state{map[string]entry{},map[string]string{},map[string]string{}}}
func validState(s state)error{
 if s.Operations==nil||s.Heads==nil||s.Genesis==nil||len(s.Operations)>512{return ErrInvalid}
 for op,e:=range s.Operations {var p Proof;if !token(op)||!digest(e.RequestDigest)||json.Unmarshal(e.Proof.Payload,&p,json.RejectUnknownMembers(true))!=nil||p.Request.OperationID!=op||p.RequestDigest!=e.RequestDigest||p.SchemaVersion!=1||p.Kind!="accepted_epoch"||p.AuthorityEpoch==0||p.JournalRevision==0{return ErrInvalid}; d,err:=RequestDigest(p.Request);if err!=nil||d!=e.RequestDigest{return ErrInvalid}}
 for scope,op:=range s.Heads {e,ok:=s.Operations[op];var p Proof;if !ok||json.Unmarshal(e.Proof.Payload,&p)!=nil||p.Request.ScopeID!=scope{return ErrInvalid}}
 for grant,op:=range s.Genesis {e,ok:=s.Operations[op];var p Proof;if !token(grant)||!ok||json.Unmarshal(e.Proof.Payload,&p)!=nil||p.GenesisGrantID!=grant||p.Request.PriorEpoch!=0{return ErrInvalid}}
 return nil
}
func New(config Config)(*Issuer,error){
 if !token(config.ProofKeyID)||len(config.ProofKey)!=ed25519.PrivateKeySize||len(config.GenesisKeys)==0||len(config.MemberKeys)==0{return nil,ErrInvalid}
 copyKeys:=func(input map[string]ed25519.PublicKey)(map[string]ed25519.PublicKey,error){out:=maps.Clone(input);for id,key:=range out{if !token(id)||len(key)!=ed25519.PublicKeySize{return nil,ErrInvalid};out[id]=slices.Clone(key)};return out,nil}
 genesis,err:=copyKeys(config.GenesisKeys);if err!=nil{return nil,err};members,err:=copyKeys(config.MemberKeys);if err!=nil{return nil,err}
 j,err:=authorityjournal.New(config.Authority,emptyState,validState);if err!=nil{return nil,err}
 return &Issuer{j,config.ProofKeyID,slices.Clone(config.ProofKey),config.Authority.AuthorityEpoch,genesis,members},nil
}

// Issue commits exactly one transition per scope and preserves every retry
// identity. No proof is returned for an unknown commit outcome; retry the same
// request to retrieve its original proof. Evidence is verified inside the CAS.
func(i *Issuer)Issue(ctx context.Context,r Request,genesis *Signed,receipts []Signed)(Signed,error){
 d,err:=RequestDigest(r);if err!=nil||i==nil||i.journal==nil{return Signed{},ErrInvalid}
 var result Signed
 err=i.journal.TransactRevision(ctx,true,func(s *state,revision uint64)error{
  if old,ok:=s.Operations[r.OperationID];ok{if old.RequestDigest!=d{return ErrConflict};result=cloneSigned(old.Proof);return nil}
  if len(s.Operations)>=512{return ErrConflict}
  var prior Proof
  if op,ok:=s.Heads[r.ScopeID];ok{if json.Unmarshal(s.Operations[op].Proof.Payload,&prior)!=nil{return ErrInvalid};if r.PriorEpoch!=prior.Request.Epoch||r.Generation<=prior.Request.Generation{return ErrConflict}}else if r.PriorEpoch!=0{return ErrMissing}
  grantID:="";receiptHashes:=[]string{}
  if r.PriorEpoch==0{
   if genesis==nil||len(receipts)!=0{return ErrInvalid};var grant GenesisGrant
   if verify(*genesis,i.genesisKeys[genesis.KeyID],&grant)!=nil||grant.Kind!="genesis_grant"||!token(grant.GrantID)||grant.RequestDigest!=d{return ErrInvalid}
   if _,used:=s.Genesis[grant.GrantID];used{return ErrConflict};grantID=grant.GrantID
  }else{
   if genesis!=nil||len(receipts)!=len(prior.Request.Members){return ErrInvalid}
   seen:=map[string]bool{}
   for _,signed:=range receipts{var receipt DrainReceipt
    // key_id must be the old member identity, not an arbitrary supplied key.
    if verify(signed,i.memberKeys[signed.KeyID],&receipt)!=nil||receipt.Kind!="old_epoch_drained_fenced"||receipt.MemberIdentity!=signed.KeyID||seen[receipt.MemberIdentity]||receipt.ScopeID!=r.ScopeID||receipt.PriorEpoch!=r.PriorEpoch||receipt.PriorGeneration!=prior.Request.Generation||receipt.RequestDigest!=d||!digest(receipt.FrontierDigest){return ErrInvalid}
    if !slices.ContainsFunc(prior.Request.Members,func(m Member)bool{return m.Identity==receipt.MemberIdentity}){return ErrInvalid};seen[receipt.MemberIdentity]=true;receiptHashes=append(receiptHashes,hash(signed.Payload))
   }
   slices.Sort(receiptHashes)
  }
  proof:=Proof{1,"accepted_epoch",r,d,i.epoch,revision,grantID,receiptHashes}
  signed,err:=SignEvidence(i.keyID,i.key,proof);if err!=nil{return err}
  s.Operations[r.OperationID]=entry{d,signed};s.Heads[r.ScopeID]=r.OperationID;if grantID!=""{s.Genesis[grantID]=r.OperationID};result=cloneSigned(signed);return nil
 })
 if err!=nil{return Signed{},err};return result,nil
}
// Load requires current GRU authority and a leader-routed barrier. It never
// returns speculative proof bytes after a failed journal transaction.
func(i *Issuer)Load(ctx context.Context,operationID string)(Signed,error){
 if i==nil||i.journal==nil||!token(operationID){return Signed{},ErrInvalid};var out Signed
 err:=i.journal.TransactRevision(ctx,false,func(s *state,_ uint64)error{e,ok:=s.Operations[operationID];if !ok{return ErrMissing};out=cloneSigned(e.Proof);return nil});if err!=nil{return Signed{},err};return out,nil
}
