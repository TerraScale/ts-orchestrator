// Package authbootstrap publishes immutable auth Raft genesis grants. It stores
// control metadata only; a persisted grant receipt does not establish readiness.
package authbootstrap

import (
 "cmp"
 "errors"
 "net/url"
 "slices"
 "strings"

 "google.golang.org/protobuf/proto"
 pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

var (
 ErrInvalid = errors.New("auth bootstrap: invalid grant or target")
 ErrConflict = errors.New("auth bootstrap: immutable genesis conflicts")
 ErrMissing = errors.New("auth bootstrap: grant missing")
)

func validID(value string) bool {
 if len(value) != 26 || value[0] > '7' { return false }
 for _, c := range value { if !strings.ContainsRune("0123456789ABCDEFGHJKMNPQRSTVWXYZ", c) { return false } }
 return true
}
func validToken(value string) bool {
 if len(value)==0 || len(value)>128 { return false }
 for _, c := range value { if c<33 || c>126 { return false } }
 return true
}
func validIdentity(value string) bool {
 u,err:=url.Parse(value)
 return validToken(value) && err==nil && u.Scheme=="spiffe" && u.Host!="" && u.Hostname()==u.Host && u.User==nil && u.RawQuery=="" && u.Fragment=="" && u.RawPath=="" && u.Path!="" && u.String()==value
}
func validIncarnation(value string) bool { return validID(value) }

// CanonicalGrant validates the complete immutable assignment. Templates omit
// only the revision and incarnation; persisted grants require both.
func CanonicalGrant(input *pb.AuthGroupBootstrapGrant, template bool) (*pb.AuthGroupBootstrapGrant,error) {
 if input==nil || proto.Size(input)>32<<10 { return nil,ErrInvalid }
 if !validID(input.GroupId) || !validToken(input.Environment) || !validToken(input.Cluster) || !validID(input.Tenant) || !validID(input.Project) || !validID(input.Database) || input.Generation!=1 || len(input.Regions)<1 || len(input.Regions)>3 || len(input.Voters)<3 || len(input.Voters)>9 || input.GenesisNode==0 || (!template && input.AuthorityRevision==0) { return nil,ErrInvalid }
 grant:=proto.Clone(input).(*pb.AuthGroupBootstrapGrant)
 slices.Sort(grant.Regions)
 for i,region:=range grant.Regions { if !validToken(region) || (i>0 && region==grant.Regions[i-1]) { return nil,ErrInvalid } }
 identities:=map[string]bool{}; members:=map[string]bool{}; genesis:=false
 for _,voter:=range grant.Voters {
  if voter==nil || voter.NodeId==0 || !validID(voter.Member) || !validIdentity(voter.SpiffeUri) || !slices.Contains(grant.Regions,voter.Region) || ((!template || voter.StorageIncarnation!="") && !validIncarnation(voter.StorageIncarnation)) || identities[voter.SpiffeUri] || members[voter.Member] { return nil,ErrInvalid }
  identities[voter.SpiffeUri]=true; members[voter.Member]=true
  genesis=genesis || voter.NodeId==grant.GenesisNode
 }
 slices.SortFunc(grant.Voters,func(a,b *pb.AuthGroupVoter)int{return cmp.Compare(a.NodeId,b.NodeId)})
 for i:=1;i<len(grant.Voters);i++ { if grant.Voters[i].NodeId==grant.Voters[i-1].NodeId {return nil,ErrInvalid} }
 if !genesis {return nil,ErrInvalid}
 return grant,nil
}
func sameTemplate(a,b *pb.AuthGroupBootstrapGrant) bool {
 left:=proto.Clone(a).(*pb.AuthGroupBootstrapGrant); right:=proto.Clone(b).(*pb.AuthGroupBootstrapGrant)
 left.AuthorityRevision=0;right.AuthorityRevision=0
 for _,v:=range left.Voters {v.StorageIncarnation=""};for _,v:=range right.Voters {v.StorageIncarnation=""}
 return proto.Equal(left,right)
}
func ValidateReceipt(receipt *pb.AuthGroupBootstrapReceipt, request *pb.AuthGroupBootstrapRequest, identity string) error {
 if receipt==nil || request==nil || request.Grant==nil || receipt.Status!=1 || receipt.OperationId!=request.OperationId || receipt.GroupId!=request.Grant.GroupId || receipt.Generation!=request.Grant.Generation || receipt.AuthorityRevision!=request.Grant.AuthorityRevision || !proto.Equal(receipt.Grant,request.Grant) { return ErrInvalid }
 for _,v:=range request.Grant.Voters { if v.SpiffeUri==identity && receipt.StorageIncarnation==v.StorageIncarnation { return nil } }
 return ErrInvalid
}
