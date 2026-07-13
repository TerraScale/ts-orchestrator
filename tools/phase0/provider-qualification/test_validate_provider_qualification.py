from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from validate_provider_qualification import (
    DEFAULT_DATASET,
    DEFAULT_SCHEMA,
    DEFAULT_SOURCES,
    load,
    validate,
)


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures/negative-cases.json"


def resolve(root: object, path: list[object]) -> object:
    current = root
    for part in path:
        current = current[part]  # type: ignore[index]
    return current


def mutate(document: object, fixture: dict[str, object], schema: dict[str, object]) -> None:
    operation = fixture["operation"]
    path = fixture["path"]
    assert isinstance(path, list)
    if operation == "set":
        parent = resolve(document, path[:-1])
        parent[path[-1]] = fixture["value"]  # type: ignore[index]
    elif operation == "delete-list-index":
        target = resolve(document, path)
        del target[fixture["value"]]  # type: ignore[index]
    elif operation == "delete-list-value":
        target = resolve(document, path)
        target.remove(fixture["value"])  # type: ignore[attr-defined]
    elif operation == "delete-key":
        target = resolve(document, path)
        del target[fixture["value"]]  # type: ignore[index]
    elif operation == "add-key":
        target = resolve(document, path)
        target[fixture["key"]] = fixture["value"]  # type: ignore[index]
    elif operation == "ambiguous-cost":
        target = resolve(document, path)
        component = {
            "amount": 1,
            "currency": "",
            "unit": "instance-hour",
            "quantity": 1,
            "sourceRef": "SRC-OCI-PRICING",
            "effectiveAt": "2026-07-13",
            "taxIncluded": False,
            "discountIncluded": False,
        }
        target["costComponents"] = {  # type: ignore[index]
            key: copy.deepcopy(component) for key in schema["costComponentFields"]  # type: ignore[index]
        }
        target["benchmark"] = {}
        target["normalizedResults"] = {}
        target["resultsComplete"] = True
    elif operation == "qualified-template-row":
        target = resolve(document, path)
        row = copy.deepcopy(target["regionRowTemplate"])  # type: ignore[index]
        row["regionKey"] = "sa-saopaulo-1"
        row["qualificationStatus"] = "qualified"
        row["disqualificationReasons"] = []
        target["rows"] = [row]  # type: ignore[index]
    else:
        raise AssertionError(f"unknown fixture operation: {operation}")


def synthetic_complete_dataset(
    blank: object,
    schema: dict[str, object],
    sources: object,
) -> object:
    """Build non-persisted structural data; values are synthetic and are not evidence."""
    assert isinstance(blank, dict)
    assert isinstance(sources, dict)
    result = copy.deepcopy(blank)
    result["status"] = "synthetic-fixture-only"
    result["normalization"] = {
        "topology": "synthetic-gru-sfo-fra",
        "baseCurrency": "BRL",
        "billingPeriodUnit": "day",
        "fxAsOf": "2026-07-13",
        "fxSourceRef": "SRC-OCI-PRICING",
        "taxTreatment": "synthetic-explicit",
        "discountCommitmentTreatment": "synthetic-explicit",
        "measurementWindow": "synthetic-seven-days",
    }
    pricing_ref = {
        "oci": "SRC-OCI-PRICING",
        "aws": "SRC-AWS-PRICING",
        "gcp": "SRC-GCP-PRICING",
        "azure": "SRC-AZURE-PRICING",
    }
    for provider in result["providers"]:
        name = provider["provider"]
        component = {
            "amount": 1,
            "currency": "USD",
            "unit": "synthetic-declared-unit",
            "quantity": 1,
            "sourceRef": pricing_ref[name],
            "effectiveAt": "2026-07-13",
            "taxIncluded": False,
            "discountIncluded": False,
        }
        provider["evidenceStatus"] = "complete"
        provider["costComponents"] = {
            key: copy.deepcopy(component) for key in schema["costComponentFields"]  # type: ignore[index]
        }
        provider["benchmark"] = {
            "workloadArtifactDigest": "sha256:synthetic-workload",
            "scriptArtifactDigest": "sha256:synthetic-script",
            "rawResultArtifactDigest": f"sha256:synthetic-{name}",
            "readLatencyMs": {"p50":1,"p95":2,"p99":3},
            "writeLatencyMs": {"p50":1,"p95":2,"p99":3},
            "fsyncLatencyMs": {"p50":1,"p95":2,"p99":3},
            "iops": {"read":1,"write":1},
            "throughputMiBps": {"read":1,"write":1},
            "noisyNeighbor": {"syntheticDeltaPercent":0},
            "onlineExpansion": {"passed":True,"synthetic":True},
            "attachTimeSeconds": 1,
            "detachTimeSeconds": 1,
            "replacementTimeSeconds": 1,
            "regionalCapacityFailure": {"recovered":True,"synthetic":True},
            "compactLoadRecovery": {"passed":True,"synthetic":True},
            "assumptions": ["synthetic structural fixture only"],
        }
        provider["normalizedResults"] = {
            "brlPerDay": 1,
            "brlPerSustainedDatabaseTransaction": 1,
            "brlPerSustainedIops": 1,
            "assumptions": ["synthetic structural fixture only"],
            "sensitivityLowBrlPerDay": 1,
            "sensitivityHighBrlPerDay": 2,
            "evidenceRefs": [pricing_ref[name]],
        }
        provider["resultsComplete"] = True
        provider["qualified"] = False
    result["decision"] = {
        "cheapestProvider": "oci",
        "selectedProvider": None,
        "normalizedResultsComplete": True,
        "decisionEvidenceRefs": list(pricing_ref.values()),
    }
    template = result["ociEligibility"]["regionRowTemplate"]
    rows = []
    oci_refs = [row["id"] for row in sources["sources"] if row["provider"] == "oci"]
    for number in range(1, 21):
        row = copy.deepcopy(template)
        populated = {
            "regionKey": f"synthetic-region-{number:02d}",
            "publicRegion": f"Synthetic Region {number:02d}",
            "realm": "synthetic-realm",
            "subscriptionEnabled": True,
            "homeGeography": "synthetic-home",
            "pairedGeography": "synthetic-pair",
            "availabilityDomains": ["synthetic-ad"],
            "faultDomains": ["synthetic-fd-1", "synthetic-fd-2", "synthetic-fd-3"],
            "a1Availability": True,
            "approvedArmFallback": "synthetic-fallback",
            "capacityProbe": {"passed":True,"synthetic":True},
            "images": ["sha256:synthetic-image"],
            "blockVolume": {"sizeGiB":1,"vpuPerGiB":1,"iops":1,"throughputMiBps":1,"onlineResizeSupported":True,"benchmarkStatus":"synthetic-pass"},
            "objectStorageAvailable": True,
            "kmsAvailable": True,
            "vaultAvailable": True,
            "loadBalancerAvailable": True,
            "iamAvailable": True,
            "dnsAvailable": True,
            "billingApiAvailable": True,
            "serviceLimits": {"synthetic":"recorded"},
            "quotaRequest": "synthetic-not-needed",
            "interRegionPaths": ["synthetic-path"],
            "interRegionLatencyMs": 1,
            "interRegionEgressPrice": {"amount":1,"currency":"BRL","unit":"GiB"},
            "dataResidencyConstraints": ["synthetic-reviewed"],
            "normalizedBrlFloorPerDay": 1,
            "qualificationTimestamp": "2026-07-13T00:00:00Z",
            "evidenceRefs": oci_refs,
            "qualificationStatus": "qualified",
            "disqualificationReasons": [],
        }
        row.update(populated)
        rows.append(row)
    result["ociEligibility"]["rows"] = rows
    result["ociEligibility"]["eligibleCount"] = 20
    result["ociEligibility"]["claimSatisfied"] = True
    return result


class ProviderQualificationValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = load(DEFAULT_SCHEMA)
        cls.dataset = load(DEFAULT_DATASET)
        cls.sources = load(DEFAULT_SOURCES)
        cls.fixtures = json.loads(FIXTURES.read_text(encoding="utf-8"))
        assert isinstance(cls.schema, dict)

    def test_blank_baseline(self) -> None:
        self.assertEqual([], validate(self.schema, self.dataset, self.sources))

    def test_synthetic_complete_structure(self) -> None:
        synthetic = synthetic_complete_dataset(self.dataset, self.schema, self.sources)
        self.assertEqual(
            [],
            validate(
                self.schema,
                synthetic,
                self.sources,
                require_checked_in_blank=False,
            ),
        )

    def test_negative_fixtures(self) -> None:
        names: list[str] = []
        for fixture in self.fixtures:
            with self.subTest(fixture=fixture["name"]):
                names.append(fixture["name"])
                schema = copy.deepcopy(self.schema)
                dataset = copy.deepcopy(self.dataset)
                sources = copy.deepcopy(self.sources)
                target = {"schema": schema, "dataset": dataset, "sources": sources}[fixture["target"]]
                mutate(target, fixture, schema)
                errors = validate(schema, dataset, sources)
                self.assertTrue(
                    any(fixture["error"] in error for error in errors),
                    f"expected {fixture['error']!r} in {errors!r}",
                )
        self.assertEqual(len(names), len(set(names)))


if __name__ == "__main__":
    unittest.main()
