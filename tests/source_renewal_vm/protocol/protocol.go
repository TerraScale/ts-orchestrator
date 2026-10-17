// Package protocol contains only the disposable Source renewal guest contract.
package protocol

const (
	ReadyPrefix  = "TS_SOURCE_RENEWAL_VM_READY="
	ResultPrefix = "TS_SOURCE_RENEWAL_VM_RESULT="
	TestName     = "TestSourceBackupRenewalIntegration"
)

type Guest struct {
	ID      string   `json:"id"`
	Modules []string `json:"modules"`
}
