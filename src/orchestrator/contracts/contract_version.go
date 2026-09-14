package contracts

// ContractVersion mirrors the C# static class ContractVersion; call sites read
// contracts.ContractVersion.Draft().
var ContractVersion contractVersion

type contractVersion struct{}

// Draft is the C# const ContractVersion.Draft.
func (contractVersion) Draft() string { return "phase0-draft" }
