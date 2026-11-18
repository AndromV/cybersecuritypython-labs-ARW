from __future__ import annotations

import math
from typing import Any, NoReturn

VARIANT_RULES: dict[int, dict[str, Any]] = {
    1: {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"},
    2: {"threshold": 8.0, "field": "attackComplexity", "expected": "LOW"},
    3: {"threshold": 7.0, "field": "privilegesRequired", "expected": "NONE"},
    4: {"threshold": 8.0, "field": "userInteraction", "expected": "NONE"},
    5: {"threshold": 7.0, "field": "confidentialityImpact", "expected": "HIGH"},
    6: {"threshold": 7.0, "field": "integrityImpact", "expected": "HIGH"},
    7: {"threshold": 7.0, "field": "availabilityImpact", "expected": "HIGH"},
    8: {"threshold": 9.0, "field": "scope", "expected": "CHANGED"},
    9: {"threshold": 5.0, "field": "attackVector", "expected": "LOCAL"},
    10: {"threshold": 6.0, "field": "privilegesRequired", "expected": "LOW"},
    11: {"threshold": 6.0, "field": "userInteraction", "expected": "REQUIRED"},
    12: {"threshold": 6.0, "field": "confidentialityImpact", "expected": "LOW"},
    13: {"threshold": 6.0, "field": "integrityImpact", "expected": "LOW"},
    14: {"threshold": 6.0, "field": "availabilityImpact", "expected": "LOW"},
    15: {"threshold": 8.0, "field": "attackComplexity", "expected": "HIGH"},
}

ALLOWED_CVSS_VALUES: dict[str, set[str]] = {
    "attackVector": {"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"},
    "attackComplexity": {"LOW", "HIGH"},
    "privilegesRequired": {"NONE", "LOW", "HIGH"},
    "userInteraction": {"NONE", "REQUIRED"},
    "scope": {"UNCHANGED", "CHANGED"},
    "confidentialityImpact": {"NONE", "LOW", "HIGH"},
    "integrityImpact": {"NONE", "LOW", "HIGH"},
    "availabilityImpact": {"NONE", "LOW", "HIGH"},
}


def _raise_contract_error(message: str) -> NoReturn:
    raise ValueError(message)


def _validate_non_empty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Field '{field_name}' must be a non-empty string.")
    return value


def _extract_english_description(cve: dict[str, Any]) -> str | None:
    if "descriptions" not in cve:
        return None
    descriptions = cve["descriptions"]
    if not isinstance(descriptions, list):
        _raise_contract_error("Field 'descriptions' must be a list.")

    selected: str | None = None
    for item in descriptions:
        if not isinstance(item, dict):
            _raise_contract_error("Each item in 'descriptions' must be an object.")
        lang = item.get("lang")
        value = item.get("value")
        if not isinstance(lang, str) or not isinstance(value, str):
            _raise_contract_error("Description 'lang' and 'value' must be strings.")
        if selected is None and lang == "en" and value.strip():
            selected = value
    return selected


def _select_cvss_v31_metric(cve: dict[str, Any]) -> dict[str, Any] | None:
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    if not isinstance(metrics, dict):
        _raise_contract_error("Field 'metrics' must be an object.")

    if "cvssMetricV31" not in metrics:
        return None
    metric_list = metrics["cvssMetricV31"]
    if not isinstance(metric_list, list):
        _raise_contract_error("Field 'cvssMetricV31' must be a list.")
    if not metric_list:
        return None

    for entry in metric_list:
        if not isinstance(entry, dict):
            _raise_contract_error("Each CVSS v3.1 entry must be an object.")

    for entry in metric_list:
        if entry.get("type") == "Primary":
            return entry
    return metric_list[0]


def extract_record(payload: Any, cve_id: str) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        _raise_contract_error("Payload must be a JSON object.")
    if "vulnerabilities" not in payload or not isinstance(
        payload["vulnerabilities"], list
    ):
        raise ValueError("Payload must contain a 'vulnerabilities' list.")

    vulnerabilities = payload["vulnerabilities"]
    if len(vulnerabilities) == 0:
        return None
    if len(vulnerabilities) > 1:
        raise ValueError("Expected at most one vulnerability record.")

    wrapper = vulnerabilities[0]
    if not isinstance(wrapper, dict) or not isinstance(wrapper.get("cve"), dict):
        _raise_contract_error("Vulnerability wrapper must contain a 'cve' object.")

    cve = wrapper["cve"]
    record_id = _validate_non_empty_str(cve.get("id"), "cve.id")
    if record_id != cve_id:
        raise ValueError(f"CVE ID mismatch: expected {cve_id}, got {record_id}.")

    vuln_status: str | None = None
    if "vulnStatus" in cve:
        vuln_status = _validate_non_empty_str(cve["vulnStatus"], "vulnStatus")

    description = _extract_english_description(cve)

    base_record: dict[str, Any] = {
        "cve_id": record_id,
        "vuln_status": vuln_status,
        "description": description,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "cvss_data": None,
    }

    if vuln_status == "Rejected" or vuln_status is None:
        return base_record

    selected_metric = _select_cvss_v31_metric(cve)
    if selected_metric is None:
        return base_record

    cvss_data = selected_metric.get("cvssData")
    if not isinstance(cvss_data, dict):
        _raise_contract_error("Selected CVSS entry must contain a 'cvssData' object.")

    raw_score = cvss_data.get("baseScore")
    if (
        isinstance(raw_score, bool)
        or not isinstance(raw_score, (int, float))
        or not math.isfinite(raw_score)
        or not (0.0 <= float(raw_score) <= 10.0)
    ):
        raise ValueError("Field 'baseScore' must be a finite number between 0 and 10.")

    cvss_version: str | None = None
    if "version" in cvss_data:
        cvss_version = _validate_non_empty_str(cvss_data["version"], "cvssData.version")
        if cvss_version != "3.1":
            raise ValueError("Field 'cvssData.version' must equal '3.1'.")

    vector: str | None = None
    if "vectorString" in cvss_data:
        vector = _validate_non_empty_str(
            cvss_data["vectorString"], "cvssData.vectorString"
        )

    score_source: str | None = None
    if "source" in selected_metric:
        score_source = _validate_non_empty_str(
            selected_metric["source"], "metric.source"
        )

    base_record.update(
        {
            "cvss_version": cvss_version,
            "score": float(raw_score),
            "score_source": score_source,
            "vector": vector,
            "cvss_data": dict(cvss_data),
        }
    )
    return base_record


def build_report(
    record: dict[str, Any] | None,
    cve_id: str,
    variant: int,
) -> dict[str, Any]:
    if (
        isinstance(variant, bool)
        or not isinstance(variant, int)
        or variant not in VARIANT_RULES
    ):
        raise ValueError("Variant must be an integer between 1 and 15.")
    _validate_non_empty_str(cve_id, "cve_id")

    rule = dict(VARIANT_RULES[variant])
    report: dict[str, Any] = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": rule,
        "observed": None,
        "decision": "not_found",
    }

    if record is None:
        return report

    if not isinstance(record, dict):
        _raise_contract_error("Record must be a dictionary or None.")

    vuln_status = record.get("vuln_status")
    description = record.get("description")
    report["vuln_status"] = vuln_status
    report["description"] = description

    if vuln_status == "Rejected":
        report["decision"] = "rejected"
        return report

    score = record.get("score")
    cvss_data = record.get("cvss_data")
    if vuln_status is None or score is None or not isinstance(cvss_data, dict):
        report["decision"] = "insufficient_data"
        return report

    report["cvss_version"] = record.get("cvss_version")
    report["score"] = score
    report["score_source"] = record.get("score_source")
    report["vector"] = record.get("vector")

    target_field = rule["field"]
    if target_field not in cvss_data:
        report["decision"] = "insufficient_data"
        return report

    observed_value = cvss_data[target_field]
    allowed_values = ALLOWED_CVSS_VALUES[target_field]
    if not isinstance(observed_value, str) or observed_value not in allowed_values:
        raise ValueError(f"Invalid value for '{target_field}': {observed_value!r}.")

    report["observed"] = observed_value
    if score >= rule["threshold"] and observed_value == rule["expected"]:
        report["decision"] = "review"
    else:
        report["decision"] = "other"

    return report
