#!/usr/bin/env python3
"""Deterministically validate the blank provider/TCO qualification evidence contract."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SCHEMA = ROOT / "testlab/pins/provider-qualification-schema.json"
DEFAULT_DATASET = ROOT / "testlab/pins/provider-qualification-blank.json"
DEFAULT_SOURCES = ROOT / "testlab/pins/provider-source-catalog.json"

PROVIDERS = {"oci", "aws", "gcp", "azure"}
SOURCE_TOPICS = {
    "regions", "armCompute", "blockStorage", "serviceAvailability", "pricing", "billingExport",
}
SOURCE_HOSTS = {
    "docs.oracle.com", "docs.aws.amazon.com", "cloud.google.com", "docs.cloud.google.com",
    "learn.microsoft.com", "azure.microsoft.com",
}
SCHEMA_KEYS = {
    "schemaVersion", "asOf", "status", "productionQualified", "requiredProviders",
    "minimumOciEligibleRegions", "maximumEvidenceAgeDays", "costComponentFields",
    "costValueFields", "benchmarkFields", "latencyPercentileFields", "ociRegionFields",
    "ociBlockVolumeFields", "sourceCatalogRequiredTopics",
}
DATASET_KEYS = {
    "schemaVersion", "schemaRef", "asOf", "status", "productionQualified",
    "normalization", "providers", "decision", "ociEligibility", "sourceCatalogRef",
}
NORMALIZATION_KEYS = {
    "topology", "baseCurrency", "billingPeriodUnit", "fxAsOf", "fxSourceRef",
    "taxTreatment", "discountCommitmentTreatment", "measurementWindow",
}
PROVIDER_KEYS = {
    "provider", "evidenceStatus", "costComponents", "benchmark", "normalizedResults",
    "resultsComplete", "qualified",
}
DECISION_KEYS = {
    "cheapestProvider", "selectedProvider", "normalizedResultsComplete", "decisionEvidenceRefs",
}
OCI_ELIGIBILITY_KEYS = {
    "requiredMinimum", "eligibleCount", "claimSatisfied", "regionRowTemplate", "rows",
}
SOURCE_CATALOG_KEYS = {"schemaVersion", "asOf", "status", "productionQualified", "sources"}
SOURCE_KEYS = {"id", "provider", "topic", "url", "checkedAt", "claim"}
NORMALIZED_RESULT_KEYS = {
    "brlPerDay", "brlPerSustainedDatabaseTransaction", "brlPerSustainedIops",
    "assumptions", "sensitivityLowBrlPerDay", "sensitivityHighBrlPerDay", "evidenceRefs",
}
SECRET_NAME = re.compile(r"(?i)(secret|token|password|private.?key|credential)")
SOURCE_ID = re.compile(r"^SRC-(?:OCI|AWS|GCP|AZURE)-[A-Z0-9-]+$")
EXPECTED_COST_COMPONENTS = {
    "compute", "bootVolumes", "dataVolumes", "natsVolumes", "observabilityVolumes",
    "provisionedIops", "provisionedThroughput", "snapshots", "backups",
    "interRegionEgress", "internetEgress", "publicIpv4", "natGateways",
    "loadBalancers", "objectRequests", "objectStorage", "kms", "secrets", "logs",
    "metrics", "artifactStorage", "support", "taxes", "fxSensitivity",
    "discountsCommitments", "idleFloor", "burstCost", "engineerOperationalCost",
}
EXPECTED_COST_VALUE_FIELDS = {
    "amount", "currency", "unit", "quantity", "sourceRef", "effectiveAt",
    "taxIncluded", "discountIncluded",
}
EXPECTED_BENCHMARK_FIELDS = {
    "workloadArtifactDigest", "scriptArtifactDigest", "rawResultArtifactDigest",
    "readLatencyMs", "writeLatencyMs", "fsyncLatencyMs", "iops", "throughputMiBps",
    "noisyNeighbor", "onlineExpansion", "attachTimeSeconds", "detachTimeSeconds",
    "replacementTimeSeconds", "regionalCapacityFailure", "compactLoadRecovery", "assumptions",
}
EXPECTED_PERCENTILES = {"p50", "p95", "p99"}
EXPECTED_OCI_REGION_FIELDS = {
    "regionKey", "publicRegion", "realm", "subscriptionEnabled", "homeGeography",
    "pairedGeography", "availabilityDomains", "faultDomains", "a1Availability",
    "approvedArmFallback", "capacityProbe", "images", "blockVolume",
    "objectStorageAvailable", "kmsAvailable", "vaultAvailable", "loadBalancerAvailable",
    "iamAvailable", "dnsAvailable", "billingApiAvailable", "serviceLimits", "quotaRequest",
    "interRegionPaths", "interRegionLatencyMs", "interRegionEgressPrice",
    "dataResidencyConstraints", "normalizedBrlFloorPerDay", "qualificationTimestamp",
    "evidenceRefs", "qualificationStatus", "disqualificationReasons",
}
EXPECTED_OCI_BLOCK_FIELDS = {
    "sizeGiB", "vpuPerGiB", "iops", "throughputMiBps", "onlineResizeSupported",
    "benchmarkStatus",
}


def load(path: Path) -> object:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def exact_keys(value: object, expected: set[str], where: str, errors: list[str]) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{where}: expected object")
        return False
    actual = set(value)
    if expected - actual:
        errors.append(f"{where}: missing fields {sorted(expected - actual)}")
    if actual - expected:
        errors.append(f"{where}: unknown fields {sorted(actual - expected)}")
    return actual == expected


def exact_string_set(value: object, expected: set[str], where: str, errors: list[str]) -> None:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        errors.append(f"{where}: expected string list")
    elif len(value) != len(set(value)) or set(value) != expected:
        errors.append(f"{where}: field set drift")


def parse_date(value: object, where: str, errors: list[str]) -> date | None:
    if not isinstance(value, str):
        errors.append(f"{where}: expected ISO date")
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        errors.append(f"{where}: expected ISO date")
        return None


def scan_secret_fields(value: object, where: str, errors: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key != "secrets" and SECRET_NAME.search(str(key)):
                errors.append(f"{where}.{key}: secret-bearing fields are prohibited")
            scan_secret_fields(child, f"{where}.{key}", errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            scan_secret_fields(child, f"{where}[{index}]", errors)


def validate_sources(catalog: object, schema: dict[str, object], errors: list[str]) -> set[str]:
    exact_keys(catalog, SOURCE_CATALOG_KEYS, "sources", errors)
    if not isinstance(catalog, dict):
        return set()
    if catalog.get("schemaVersion") != 1 or catalog.get("status") != "source-map-only":
        errors.append("sources: expected schemaVersion 1 and source-map-only status")
    if catalog.get("productionQualified") is not False:
        errors.append("sources.productionQualified: must be false")
    as_of = parse_date(schema.get("asOf"), "schema.asOf", errors)
    if catalog.get("asOf") != schema.get("asOf"):
        errors.append("sources.asOf: must equal schema.asOf")
    maximum_age = schema.get("maximumEvidenceAgeDays")
    if not isinstance(maximum_age, int) or maximum_age <= 0:
        errors.append("schema.maximumEvidenceAgeDays: expected positive integer")
        maximum_age = 0
    rows = catalog.get("sources")
    if not isinstance(rows, list) or not rows:
        errors.append("sources.sources: expected non-empty list")
        rows = []
    ids: list[str] = []
    coverage: set[tuple[str, str]] = set()
    for index, row in enumerate(rows):
        where = f"sources.sources[{index}]"
        exact_keys(row, SOURCE_KEYS, where, errors)
        if not isinstance(row, dict):
            continue
        source_id = row.get("id")
        if not isinstance(source_id, str) or not SOURCE_ID.fullmatch(source_id):
            errors.append(f"{where}.id: invalid stable source ID")
        else:
            ids.append(source_id)
        provider, topic = row.get("provider"), row.get("topic")
        if provider not in PROVIDERS or topic not in SOURCE_TOPICS:
            errors.append(f"{where}: unknown provider/topic")
        else:
            coverage.add((provider, topic))
        url = row.get("url")
        if not isinstance(url, str):
            errors.append(f"{where}.url: expected official HTTPS URL")
        else:
            parts = urlsplit(url)
            if parts.scheme != "https" or parts.netloc not in SOURCE_HOSTS:
                errors.append(f"{where}.url: source must be an allowed official host")
            if parts.query or parts.fragment or parts.username or parts.password:
                errors.append(f"{where}.url: query, fragment, and userinfo are prohibited")
        checked = parse_date(row.get("checkedAt"), f"{where}.checkedAt", errors)
        if as_of and checked and (checked > as_of or (as_of - checked).days > maximum_age):
            errors.append(f"{where}.checkedAt: stale or future evidence")
        claim = row.get("claim")
        if not isinstance(claim, str) or not claim.strip():
            errors.append(f"{where}.claim: expected bounded source-map statement")
        elif (
            "qualified" in claim.lower()
            and "unknown" not in claim.lower()
            and "not " not in claim.lower()
            and "no " not in claim.lower()
        ):
            errors.append(f"{where}.claim: qualification claim is prohibited")
    if len(ids) != len(set(ids)):
        errors.append("sources.sources: duplicate stable source IDs")
    expected_coverage = {(provider, topic) for provider in PROVIDERS for topic in SOURCE_TOPICS}
    if coverage != expected_coverage:
        errors.append("sources.sources: incomplete provider/topic coverage")
    return set(ids)


def validate_cost_components(
    value: object,
    schema: dict[str, object],
    source_ids: set[str],
    where: str,
    errors: list[str],
) -> None:
    fields = set(schema["costComponentFields"])  # type: ignore[arg-type]
    value_fields = set(schema["costValueFields"])  # type: ignore[arg-type]
    if not exact_keys(value, fields, where, errors) or not isinstance(value, dict):
        return
    for field, component in value.items():
        component_where = f"{where}.{field}"
        if component is None:
            errors.append(f"{component_where}: complete cost results cannot contain null")
            continue
        if not exact_keys(component, value_fields, component_where, errors) or not isinstance(component, dict):
            continue
        for key in ("currency", "unit", "sourceRef", "effectiveAt"):
            if not isinstance(component.get(key), str) or not component[key].strip():
                errors.append(f"{component_where}.{key}: currency/unit/evidence ambiguity is prohibited")
        if component.get("sourceRef") not in source_ids:
            errors.append(f"{component_where}.sourceRef: unknown evidence reference")
        if not isinstance(component.get("amount"), (int, float)) or component["amount"] < 0:
            errors.append(f"{component_where}.amount: expected non-negative number")
        if not isinstance(component.get("quantity"), (int, float)) or component["quantity"] < 0:
            errors.append(f"{component_where}.quantity: expected non-negative number")
        for key in ("taxIncluded", "discountIncluded"):
            if not isinstance(component.get(key), bool):
                errors.append(f"{component_where}.{key}: expected explicit boolean")


def validate_benchmark(value: object, schema: dict[str, object], where: str, errors: list[str]) -> None:
    fields = set(schema["benchmarkFields"])  # type: ignore[arg-type]
    if not exact_keys(value, fields, where, errors) or not isinstance(value, dict):
        return
    for key, child in value.items():
        if child is None:
            errors.append(f"{where}.{key}: complete benchmark cannot contain null")
    percentiles = set(schema["latencyPercentileFields"])  # type: ignore[arg-type]
    for key in ("readLatencyMs", "writeLatencyMs", "fsyncLatencyMs"):
        exact_keys(value.get(key), percentiles, f"{where}.{key}", errors)


def validate_region_row(
    row: object,
    schema: dict[str, object],
    source_ids: set[str],
    where: str,
    errors: list[str],
) -> bool:
    fields = set(schema["ociRegionFields"])  # type: ignore[arg-type]
    if not exact_keys(row, fields, where, errors) or not isinstance(row, dict):
        return False
    status = row.get("qualificationStatus")
    if status not in {"not-qualified", "qualified"}:
        errors.append(f"{where}.qualificationStatus: invalid state")
    evidence = row.get("evidenceRefs")
    if not isinstance(evidence, list) or any(ref not in source_ids for ref in evidence):
        errors.append(f"{where}.evidenceRefs: unknown evidence reference")
    reasons = row.get("disqualificationReasons")
    if not isinstance(reasons, list):
        errors.append(f"{where}.disqualificationReasons: expected list")
    block = row.get("blockVolume")
    if block is not None:
        exact_keys(block, set(schema["ociBlockVolumeFields"]), f"{where}.blockVolume", errors)  # type: ignore[arg-type]
    if status == "qualified":
        for key, value in row.items():
            if key != "disqualificationReasons" and (value is None or value == []):
                errors.append(f"{where}.{key}: qualified row cannot contain unknown evidence")
        if reasons != []:
            errors.append(f"{where}.disqualificationReasons: qualified row must have no reasons")
        return True
    if not isinstance(reasons, list) or not reasons:
        errors.append(f"{where}.disqualificationReasons: unqualified row requires reasons")
    return False


def validate(
    schema: object,
    dataset: object,
    catalog: object,
    *,
    require_checked_in_blank: bool = True,
) -> list[str]:
    errors: list[str] = []
    exact_keys(schema, SCHEMA_KEYS, "schema", errors)
    exact_keys(dataset, DATASET_KEYS, "dataset", errors)
    if not isinstance(schema, dict) or not isinstance(dataset, dict):
        return sorted(set(errors))
    if schema.get("schemaVersion") != 1 or schema.get("status") != "blank-contract-only":
        errors.append("schema: expected version 1 blank-contract-only")
    if schema.get("productionQualified") is not False:
        errors.append("schema.productionQualified: must be false")
    exact_string_set(schema.get("requiredProviders"), PROVIDERS, "schema.requiredProviders", errors)
    exact_string_set(schema.get("sourceCatalogRequiredTopics"), SOURCE_TOPICS, "schema.sourceCatalogRequiredTopics", errors)
    if schema.get("minimumOciEligibleRegions") != 20:
        errors.append("schema.minimumOciEligibleRegions: expected 20")
    expected_field_sets = {
        "costComponentFields": EXPECTED_COST_COMPONENTS,
        "costValueFields": EXPECTED_COST_VALUE_FIELDS,
        "benchmarkFields": EXPECTED_BENCHMARK_FIELDS,
        "latencyPercentileFields": EXPECTED_PERCENTILES,
        "ociRegionFields": EXPECTED_OCI_REGION_FIELDS,
        "ociBlockVolumeFields": EXPECTED_OCI_BLOCK_FIELDS,
    }
    for key, expected in expected_field_sets.items():
        exact_string_set(schema.get(key), expected, f"schema.{key}", errors)

    source_ids = validate_sources(catalog, schema, errors)
    allowed_statuses = {"not-qualified"} if require_checked_in_blank else {"not-qualified", "synthetic-fixture-only"}
    if dataset.get("schemaVersion") != 1 or dataset.get("status") not in allowed_statuses:
        errors.append("dataset: unexpected version or evidence status")
    if dataset.get("productionQualified") is not False:
        errors.append("dataset.productionQualified: must be false")
    if dataset.get("asOf") != schema.get("asOf"):
        errors.append("dataset.asOf: must equal schema.asOf")
    if dataset.get("schemaRef") != "testlab/pins/provider-qualification-schema.json":
        errors.append("dataset.schemaRef: unexpected schema reference")
    if dataset.get("sourceCatalogRef") != "testlab/pins/provider-source-catalog.json":
        errors.append("dataset.sourceCatalogRef: unexpected catalog reference")

    normalization = dataset.get("normalization")
    exact_keys(normalization, NORMALIZATION_KEYS, "dataset.normalization", errors)
    if require_checked_in_blank and isinstance(normalization, dict) and any(value is not None for value in normalization.values()):
        errors.append("dataset.normalization: blank dataset normalization fields must remain null")
    providers = dataset.get("providers")
    if not isinstance(providers, list) or len(providers) != 4:
        errors.append("dataset.providers: expected exactly four provider rows")
        providers = []
    provider_names: list[str] = []
    provider_rows_by_name: dict[str, dict[str, object]] = {}
    complete_providers = 0
    for index, provider in enumerate(providers):
        where = f"dataset.providers[{index}]"
        exact_keys(provider, PROVIDER_KEYS, where, errors)
        if not isinstance(provider, dict):
            continue
        name = provider.get("provider")
        if name not in PROVIDERS:
            errors.append(f"{where}.provider: unknown provider")
        else:
            provider_names.append(name)
            provider_rows_by_name[name] = provider
        if provider.get("evidenceStatus") not in {"unknown", "complete"}:
            errors.append(f"{where}.evidenceStatus: invalid state")
        if require_checked_in_blank and provider.get("evidenceStatus") != "unknown":
            errors.append(f"{where}.evidenceStatus: blank dataset must remain unknown")
        complete = provider.get("resultsComplete")
        if not isinstance(complete, bool):
            errors.append(f"{where}.resultsComplete: expected boolean")
        if not isinstance(provider.get("qualified"), bool):
            errors.append(f"{where}.qualified: expected boolean")
        if require_checked_in_blank and provider.get("qualified") is not False:
            errors.append(f"{where}.qualified: qualification claims are prohibited in blank dataset")
        if provider.get("qualified") is True and complete is not True:
            errors.append(f"{where}.qualified: qualification requires complete results")
        if complete is True:
            complete_providers += 1
            validate_cost_components(
                provider.get("costComponents"), schema, source_ids, f"{where}.costComponents", errors
            )
            validate_benchmark(provider.get("benchmark"), schema, f"{where}.benchmark", errors)
            exact_keys(provider.get("normalizedResults"), NORMALIZED_RESULT_KEYS, f"{where}.normalizedResults", errors)
            normalized = provider.get("normalizedResults")
            if isinstance(normalized, dict) and any(value is None or value == [] for value in normalized.values()):
                errors.append(f"{where}.normalizedResults: complete results cannot contain unknown values")
            if isinstance(normalized, dict):
                normalized_refs = normalized.get("evidenceRefs")
                if not isinstance(normalized_refs, list) or any(ref not in source_ids for ref in normalized_refs):
                    errors.append(f"{where}.normalizedResults.evidenceRefs: unknown evidence reference")
        elif any(provider.get(key) is not None for key in ("costComponents", "benchmark", "normalizedResults")):
            errors.append(f"{where}: partial results require resultsComplete false with all result sections null")
    if set(provider_names) != PROVIDERS or len(provider_names) != len(set(provider_names)):
        errors.append("dataset.providers: provider set drift or duplicate")

    decision = dataset.get("decision")
    exact_keys(decision, DECISION_KEYS, "dataset.decision", errors)
    if isinstance(decision, dict):
        winner = decision.get("cheapestProvider")
        selected = decision.get("selectedProvider")
        if winner is not None or selected is not None:
            if winner not in PROVIDERS and winner is not None:
                errors.append("dataset.decision.cheapestProvider: unknown provider")
            if complete_providers != 4 or decision.get("normalizedResultsComplete") is not True:
                errors.append("dataset.decision: provider winner/selection requires complete normalized results")
            if isinstance(normalization, dict) and any(value is None for value in normalization.values()):
                errors.append("dataset.decision: provider winner/selection requires complete normalization policy")
            if isinstance(normalization, dict) and normalization.get("fxSourceRef") not in source_ids:
                errors.append("dataset.normalization.fxSourceRef: unknown evidence reference")
        if selected in PROVIDERS and provider_rows_by_name.get(selected, {}).get("qualified") is not True:
            errors.append("dataset.decision.selectedProvider: selection requires a qualified provider, not price alone")
        if not isinstance(decision.get("normalizedResultsComplete"), bool):
            errors.append("dataset.decision.normalizedResultsComplete: expected boolean")
        if require_checked_in_blank and decision.get("normalizedResultsComplete") is not False:
            errors.append("dataset.decision.normalizedResultsComplete: blank dataset must remain false")
        decision_refs = decision.get("decisionEvidenceRefs")
        if not isinstance(decision_refs, list) or any(ref not in source_ids for ref in decision_refs):
            errors.append("dataset.decision.decisionEvidenceRefs: unknown evidence reference")
        if require_checked_in_blank and decision_refs != []:
            errors.append("dataset.decision.decisionEvidenceRefs: blank dataset must remain empty")

    eligibility = dataset.get("ociEligibility")
    exact_keys(eligibility, OCI_ELIGIBILITY_KEYS, "dataset.ociEligibility", errors)
    if isinstance(eligibility, dict):
        if eligibility.get("requiredMinimum") != 20:
            errors.append("dataset.ociEligibility.requiredMinimum: expected 20")
        template = eligibility.get("regionRowTemplate")
        validate_region_row(template, schema, source_ids, "dataset.ociEligibility.regionRowTemplate", errors)
        if isinstance(template, dict):
            for key, value in template.items():
                if key not in {"evidenceRefs", "qualificationStatus", "disqualificationReasons"} and value is not None:
                    errors.append(f"dataset.ociEligibility.regionRowTemplate.{key}: blank template fields must be null")
        rows = eligibility.get("rows")
        if not isinstance(rows, list):
            errors.append("dataset.ociEligibility.rows: expected list")
            rows = []
        qualified_count = 0
        region_keys: list[str] = []
        for index, row in enumerate(rows):
            qualified_count += validate_region_row(
                row, schema, source_ids, f"dataset.ociEligibility.rows[{index}]", errors
            )
            if isinstance(row, dict) and isinstance(row.get("regionKey"), str):
                region_keys.append(row["regionKey"])
        if len(region_keys) != len(set(region_keys)):
            errors.append("dataset.ociEligibility.rows: duplicate regionKey")
        if eligibility.get("eligibleCount") != qualified_count:
            errors.append("dataset.ociEligibility.eligibleCount: must equal fully qualified row count")
        expected_claim = qualified_count >= 20
        if eligibility.get("claimSatisfied") is not expected_claim:
            errors.append("dataset.ociEligibility.claimSatisfied: false >=20 eligibility claim")
        if require_checked_in_blank and rows != []:
            errors.append("dataset.ociEligibility.rows: checked-in blank dataset must have no evidence rows")

    scan_secret_fields(dataset, "dataset", errors)
    scan_secret_fields(catalog, "sources", errors)
    return sorted(set(errors))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCES)
    args = parser.parse_args(argv)
    try:
        schema, dataset, catalog = load(args.schema), load(args.dataset), load(args.sources)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"invalid provider qualification evidence: {exc}", file=sys.stderr)
        return 1
    errors = validate(schema, dataset, catalog)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("validated blank 4-provider contract, 0 OCI eligible rows, and official source freshness; no winner or qualification")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
