package tbep

import (
 "context"
 "errors"

 "google.golang.org/grpc/metadata"
 "terrascale.tech/orchestrator/src/orchestrator/authbootstrap"
 pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

type AuthBootstrapClient struct{ transport *Client;rpc pb.AuthGroupBootstrapServiceClient;identity string }
func NewAuthBootstrap(config Config)(*AuthBootstrapClient,error){
 if config.Tenant!="" || config.Project!="" || config.Database!=""{return nil,errors.New("auth bootstrap requires host scope")}
 transport,err:=newClient(config,false);if err!=nil{return nil,err}
 return &AuthBootstrapClient{transport:transport,rpc:pb.NewAuthGroupBootstrapServiceClient(transport.conn),identity:config.ServerIdentity},nil
}
func(c *AuthBootstrapClient)Close()error{return c.transport.Close()}
func(c *AuthBootstrapClient)Principal()string{return c.transport.principal}
func(c *AuthBootstrapClient)ServerIdentity()string{return c.identity}
func(c *AuthBootstrapClient)Identity(ctx context.Context)(*pb.AuthStorageIdentity,error){
 ctx,cancel:=context.WithTimeout(ctx,c.transport.timeout);defer cancel()
 return c.rpc.Identity(metadata.NewOutgoingContext(ctx,c.transport.scope.Copy()),&pb.AuthStorageIdentityRequest{})
}
func(c *AuthBootstrapClient)Bootstrap(ctx context.Context,request *pb.AuthGroupBootstrapRequest)(*pb.AuthGroupBootstrapReceipt,error){
 if request==nil || !validMetadata(request.OperationId,128){return nil,authbootstrap.ErrInvalid}
 if _,err:=authbootstrap.CanonicalGrant(request.Grant,false);err!=nil{return nil,err}
 ctx,cancel:=context.WithTimeout(ctx,c.transport.timeout);defer cancel()
 scope:=c.transport.scope.Copy();scope.Set("x-tb-idempotency-key",request.OperationId)
 receipt,err:=c.rpc.Bootstrap(metadata.NewOutgoingContext(ctx,scope),request)
 if err!=nil{return nil,err};if err:=authbootstrap.ValidateReceipt(receipt,request,c.identity);err!=nil{return nil,err};return receipt,nil
}
