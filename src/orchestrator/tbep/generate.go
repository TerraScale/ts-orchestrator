package tbep

// Run with protoc 34.1, protoc-gen-go 1.36.12 and protoc-gen-go-grpc 1.6.2 on PATH.
// The M options relocate generated Go imports; the pinned wire contract is unchanged.
//go:generate protoc -I contracts --go_out=wire --go_opt=paths=source_relative --go_opt=Mterrabase/v1/engine.proto=terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1 --go_opt=Mterrabase/v1/family.proto=terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1 --go-grpc_out=wire --go-grpc_opt=paths=source_relative --go-grpc_opt=Mterrabase/v1/engine.proto=terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1 terrabase/v1/engine.proto terrabase/v1/family.proto
