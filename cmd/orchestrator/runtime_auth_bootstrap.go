package main

import (
 "context"
 "errors"
 "time"

 "terrascale.tech/orchestrator/src/orchestrator/authbootstrap"
 "terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
 pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

type productionAuthBootstrapConfig struct {
 Targets []productionPlacementTarget
 Grants []*pb.AuthGroupBootstrapGrant
}
type productionAuthBootstrap struct {service *authbootstrap.Service;grants []*pb.AuthGroupBootstrapGrant}
func newProductionAuthBootstrap(config productionAuthBootstrapConfig,session globalWorkerSession)(*productionAuthBootstrap,error){
 if len(config.Targets)==0 || len(config.Targets)>128 || len(config.Grants)==0 || len(config.Grants)>32{return nil,errors.New("auth bootstrap: admitted targets and explicit auth domain grants required")}
 journal,err:=authbootstrap.NewJournal(authorityjournal.Config{Connection:session.Connection,CandidateID:session.Lease.CandidateId,AuthorityEpoch:uint64(session.Lease.Epoch),LeaseID:session.Lease.LeaseId});if err!=nil{return nil,err}
 targets:=make([]authbootstrap.Target,0,len(config.Targets));admitted:=map[string]bool{}
 for _,host:=range config.Targets{target,err:=authbootstrap.NewRemoteTarget(session.Connection,host.ServerIdentity,host.Principal,10*time.Second);if err!=nil{return nil,err};targets=append(targets,target);admitted[host.ServerIdentity]=true}
 service,err:=authbootstrap.New(journal,targets,session.CheckEffectAuthority);if err!=nil{return nil,err}
 result:=&productionAuthBootstrap{service:service};groups:=map[string]bool{};databases:=map[string]bool{}
 for _,input:=range config.Grants{
  grant,err:=authbootstrap.CanonicalGrant(input,true);if err!=nil{return nil,err}
  scope:=grant.Environment+"/"+grant.Cluster+"/"+grant.Tenant+"/"+grant.Project+"/"+grant.Database
  if grant.AuthorityRevision!=0 || groups[grant.GroupId] || databases[scope]{return nil,authbootstrap.ErrConflict}
  for _,voter:=range grant.Voters{if !admitted[voter.SpiffeUri]{return nil,authbootstrap.ErrInvalid}}
  groups[grant.GroupId]=true;databases[scope]=true;result.grants=append(result.grants,grant)
 }
 return result,nil
}
func (bootstrap *productionAuthBootstrap) Reconcile(ctx context.Context)error{
 var failures []error
 for _,grant:=range bootstrap.grants{err:=bootstrap.service.Reconcile(ctx,grant);if errors.Is(err,authorityjournal.ErrFenced){return err};if err!=nil{failures=append(failures,err)}}
 return errors.Join(failures...)
}
