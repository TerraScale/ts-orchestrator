// Package databaseadmission durably accepts immutable database creation intent.
// A pending placement receipt never proves a database ready to serve.
package databaseadmission

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json/v2"
 "errors"
 "reflect"
 "regexp"
 "slices"
 "strings"

 "terrascale.tech/orchestrator/src/orchestrator/keylease"
)

var ErrInvalid = errors.New("database admission: invalid request or plan")
var ErrConflict = errors.New("database admission: immutable create conflict")

type Request struct {
 Environment string `json:"environment"`
 TenantID string `json:"tenant_id"`
 ProjectID string `json:"project_id"`
 Name string `json:"name"`
 OperationID string `json:"operation_id"`
 Regions []string `json:"regions"`
 Residency string `json:"residency"`
}
type Target struct {
 ServerIdentity string
 MemberID string
 Region string
 Provision keylease.ProvisionTarget
 Proposal []byte
 Installed bool
 Proposed bool
}
type Record struct {
 Revision uint64
 Request Request
 DatabaseID string
 KeyVersion string
 State string
 Targets []Target
 Wrapped []keylease.Entry
}
type Journal interface {
 Load(context.Context,string)(Record,bool,error)
 Save(context.Context,string,uint64,Record)(uint64,error)
 List(context.Context)([]Record,error)
}
var canonicalID = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
var databaseName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
var environmentName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)
func ScopeKey(r Request) string {
 value,_ := json.Marshal([]string{r.Environment,r.TenantID,r.ProjectID,r.Name})
 sum := sha256.Sum256(value)
 return hex.EncodeToString(sum[:])
}
func ValidateRequest(r Request) error {
 if !environmentName.MatchString(r.Environment)||!canonicalID.MatchString(r.TenantID)||!canonicalID.MatchString(r.ProjectID)||!databaseName.MatchString(r.Name)||len(r.OperationID)<1||len(r.OperationID)>128||len(r.Regions)<1||len(r.Regions)>3 { return ErrInvalid }
 for _, c := range r.OperationID { if c<33||c>126 { return ErrInvalid } }
 seen:=map[string]bool{}
 for _, region := range r.Regions {
  if !slices.Contains([]string{"GRU","SFO","FRA"},region)||seen[region] {return ErrInvalid};seen[region]=true
 }
 allowed:=[]string{"GRU","SFO","FRA"}
 switch r.Residency {case "", "none": case "eu-only":allowed=[]string{"FRA"};case "br-only":allowed=[]string{"GRU"};default:
  allowed=strings.Split(r.Residency,",")
  if len(allowed)>3 {return ErrInvalid}; constraints:=map[string]bool{}
  for _, region:=range allowed {if !slices.Contains([]string{"GRU","SFO","FRA"},region)||constraints[region]{return ErrInvalid};constraints[region]=true}
 }
 for _, region:=range r.Regions {if !slices.Contains(allowed,region){return ErrInvalid}}
 return nil
}
func ValidateRecord(r Record) error {
 if ValidateRequest(r.Request)!=nil||!canonicalID.MatchString(r.DatabaseID)||!canonicalID.MatchString(r.KeyVersion)||!slices.Contains([]string{"accepted","keys_provisioned","members_admitted","placement_pending"},r.State)||len(r.Targets)!=len(r.Request.Regions)*2 {return ErrInvalid}
 hosts:=map[string]bool{}; members:=map[string]bool{}; regions:=map[string]int{}
 for _, t:=range r.Targets {
  if t.ServerIdentity==""||hosts[t.ServerIdentity]||!canonicalID.MatchString(t.MemberID)||members[t.MemberID]||!slices.Contains(r.Request.Regions,t.Region)||len(t.Proposal)==0 {return ErrInvalid}
  b:=t.Provision.Binding
  if b.Environment!=r.Request.Environment||b.TenantID!=r.Request.TenantID||b.ProjectID!=r.Request.ProjectID||b.DatabaseID!=r.DatabaseID||b.KeyVersion!=r.KeyVersion||b.Region!=t.Region||b.Purpose!="data" {return ErrInvalid}
  hosts[t.ServerIdentity]=true;members[t.MemberID]=true;regions[t.Region]++
 }
 for _, region:=range r.Request.Regions {if regions[region]!=2{return ErrInvalid}}
 return nil
}
// ImmutableEqual permits progress updates, never a changed identity or plan.
func ImmutableEqual(a,b Record) bool {
 a.Revision=0;b.Revision=0;a.State="";b.State="";a.Wrapped=nil;b.Wrapped=nil
 a.Targets=slices.Clone(a.Targets);b.Targets=slices.Clone(b.Targets)
 for i:=range a.Targets {a.Targets[i].Installed=false;a.Targets[i].Proposed=false}
 for i:=range b.Targets {b.Targets[i].Installed=false;b.Targets[i].Proposed=false}
 return reflect.DeepEqual(a,b)
}
