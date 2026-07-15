namespace TerraScale.Orchestrator.Tooling;

internal static class TranslatedScriptCatalog
{
    public static readonly IReadOnlyDictionary<string, string> Replacements = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["docs/adr/validate_readiness"] = "adr-readiness",
        ["docs/adr/tests/test_validate_readiness"] = "test",
        ["docs/audits/registry/check_registry_audit"] = "registry-audit",
        ["docs/decisions/validate_owner_decision_packet"] = "owner-decisions",
        ["docs/decisions/tests/test_owner_decision_packet"] = "test",
        ["testlab/conformance/check_smolvm_host"] = "smolvm-host",
        ["testlab/nats/run_local_l0c_smoke"] = "nats-smoke",
        ["testlab/nats/validate_nats_readiness"] = "nats-readiness",
        ["testlab/nats/tests/test_validate_nats_readiness"] = "test",
        ["tools/mutation/validate_mutation_evidence"] = "mutation-evidence",
        ["tools/mutation/test_validate_mutation_evidence"] = "test",
        ["tools/nats-l0c/validate_l0c_foundation"] = "nats-l0c",
        ["tools/nats-l0c/test_validate_l0c_foundation"] = "test",
        ["tools/phase0/delivery-inventory/generate_inventory"] = "delivery-inventory-generate",
        ["tools/phase0/delivery-inventory/validate_inventory"] = "delivery-inventory-validate",
        ["tools/phase0/delivery-inventory/tests/test_validate_inventory"] = "test",
        ["tools/phase0/oci-inventory/oci_inventory"] = "oci-inventory",
        ["tools/phase0/oci-inventory/test_oci_inventory"] = "test",
        ["tools/phase0/provider-qualification/validate_provider_qualification"] = "provider-qualification",
        ["tools/phase0/provider-qualification/test_validate_provider_qualification"] = "test",
        ["tools/phase0/runtime-readiness/validate_runtime_readiness"] = "runtime-readiness",
        ["tools/phase0/runtime-readiness/test_validate_runtime_readiness"] = "test",
        ["tools/phase0/supply-chain/validate_supply_chain_pins"] = "supply-chain",
        ["tools/phase0/supply-chain/test_validate_supply_chain_pins"] = "test",
        ["tools/traceability/generate_traceability"] = "traceability-generate",
        ["tools/traceability/test_generate_traceability"] = "test",
        ["tools/traceability/validate_traceability"] = "traceability-validate",
        ["tools/traceability/test_validate_traceability"] = "test",
    };
}
