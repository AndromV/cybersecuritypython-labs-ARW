from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import analysis, api_client, main

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"


@pytest.fixture
def sample_payload() -> dict[str, Any]:
    raw = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    return copy.deepcopy(raw)


def _set_variant9_metric(
    payload: dict[str, Any],
    *,
    score: float,
    attack_vector: str = "LOCAL",
) -> dict[str, Any]:
    data = copy.deepcopy(payload)
    cvss = data["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]
    cvss["baseScore"] = score
    cvss["attackVector"] = attack_vector
    return data


# --- Analysis & Variant 9 Rule Tests ---


@pytest.mark.parametrize(
    ("score", "attack_vector", "expected_decision"),
    [
        (4.9, "LOCAL", "other"),
        (5.0, "LOCAL", "review"),
        (8.5, "LOCAL", "review"),
        (9.8, "NETWORK", "other"),
    ],
)
def test_variant9_threshold_and_feature(
    sample_payload: dict[str, Any],
    score: float,
    attack_vector: str,
    expected_decision: str,
) -> None:
    payload = _set_variant9_metric(
        sample_payload, score=score, attack_vector=attack_vector
    )
    record = analysis.extract_record(payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", variant=9)

    assert report["decision"] == expected_decision
    assert report["observed"] == attack_vector
    assert report["rule"] == {
        "threshold": 5.0,
        "field": "attackVector",
        "expected": "LOCAL",
    }


def test_not_found_returns_null_data_fields() -> None:
    payload = {"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}
    record = analysis.extract_record(payload, "CVE-2099-99999")
    report = analysis.build_report(record, "CVE-2099-99999", variant=9)

    assert record is None
    assert report["decision"] == "not_found"
    assert report["description"] is None
    assert report["vuln_status"] is None
    assert report["score"] is None
    assert report["observed"] is None
    assert report["variant"] == 9


def test_rejected_status_skips_metrics(sample_payload: dict[str, Any]) -> None:
    sample_payload["vulnerabilities"][0]["cve"]["vulnStatus"] = "Rejected"
    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", variant=9)

    assert report["vuln_status"] == "Rejected"
    assert report["decision"] == "rejected"
    assert report["score"] is None
    assert report["observed"] is None


def test_missing_metrics_gives_insufficient_data(
    sample_payload: dict[str, Any],
) -> None:
    del sample_payload["vulnerabilities"][0]["cve"]["metrics"]
    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", variant=9)

    assert report["vuln_status"] == "Analyzed"
    assert report["decision"] == "insufficient_data"
    assert report["score"] is None
    assert report["observed"] is None


def test_missing_variant_field_gives_insufficient_data(
    sample_payload: dict[str, Any],
) -> None:
    cvss = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
        "cvssData"
    ]
    del cvss["attackVector"]
    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", variant=9)

    assert report["decision"] == "insufficient_data"
    assert report["observed"] is None
    assert report["score"] == 9.8


@pytest.mark.parametrize("bad_value", [None, 123, "INVALID_VECTOR"])
def test_invalid_variant_field_raises_value_error(
    sample_payload: dict[str, Any],
    bad_value: Any,
) -> None:
    cvss = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
        "cvssData"
    ]
    cvss["attackVector"] = bad_value
    record = analysis.extract_record(sample_payload, "CVE-2099-10001")

    with pytest.raises(ValueError):
        analysis.build_report(record, "CVE-2099-10001", variant=9)


@pytest.mark.parametrize("bad_score", [True, "9.8", -1.0, 10.5, float("nan")])
def test_invalid_base_score_raises_value_error(
    sample_payload: dict[str, Any],
    bad_score: Any,
) -> None:
    cvss = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
        "cvssData"
    ]
    cvss["baseScore"] = bad_score

    with pytest.raises(ValueError):
        analysis.extract_record(sample_payload, "CVE-2099-10001")


def test_primary_metric_has_priority_over_secondary(
    sample_payload: dict[str, Any],
) -> None:
    metrics_list = sample_payload["vulnerabilities"][0]["cve"]["metrics"][
        "cvssMetricV31"
    ]
    primary_entry = copy.deepcopy(metrics_list[0])
    secondary_entry = copy.deepcopy(metrics_list[0])
    secondary_entry["type"] = "Secondary"
    secondary_entry["source"] = "secondary@example.invalid"
    secondary_entry["cvssData"]["baseScore"] = 2.0
    secondary_entry["cvssData"]["attackVector"] = "LOCAL"

    sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = [
        secondary_entry,
        primary_entry,
    ]
    record = analysis.extract_record(sample_payload, "CVE-2099-10001")

    assert record is not None
    assert record["score"] == 9.8
    assert record["score_source"] == "nvd@nist.gov"


def test_fallback_to_first_metric_when_no_primary(
    sample_payload: dict[str, Any],
) -> None:
    metrics_list = sample_payload["vulnerabilities"][0]["cve"]["metrics"][
        "cvssMetricV31"
    ]
    first_secondary = copy.deepcopy(metrics_list[0])
    first_secondary["type"] = "Secondary"
    first_secondary["source"] = "first@example.invalid"
    first_secondary["cvssData"]["baseScore"] = 6.5
    first_secondary["cvssData"]["attackVector"] = "LOCAL"

    second_secondary = copy.deepcopy(metrics_list[0])
    second_secondary["type"] = "Secondary"
    second_secondary["source"] = "second@example.invalid"
    second_secondary["cvssData"]["baseScore"] = 3.1

    sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = [
        first_secondary,
        second_secondary,
    ]
    record = analysis.extract_record(sample_payload, "CVE-2099-10001")

    assert record is not None
    assert record["score"] == 6.5
    assert record["score_source"] == "first@example.invalid"


# --- API Client Tests ---


def test_build_headers_without_and_with_key(monkeypatch: pytest.MonkeyPatch) -> None:
    assert api_client.build_headers() == {"Accept": "application/json"}

    monkeypatch.setenv("NVD_API_KEY", "   ")
    assert api_client.build_headers() == {"Accept": "application/json"}

    monkeypatch.setenv("NVD_API_KEY", "  fake-test-key-123  ")
    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "fake-test-key-123",
    }


def test_fetch_response_success(monkeypatch: pytest.MonkeyPatch) -> None:
    expected_payload = {"vulnerabilities": []}
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.return_value = expected_payload
    fake_get = Mock(return_value=response)

    monkeypatch.setattr(api_client.requests, "get", fake_get)
    result = api_client.fetch_response("CVE-2099-10001")

    assert result == expected_payload
    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10.0),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_response_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    error_response = Mock(spec=requests.Response)
    error_response.status_code = 503
    response = Mock(spec=requests.Response)
    response.raise_for_status.side_effect = requests.HTTPError(
        "Service Unavailable", response=error_response
    )

    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))
    with pytest.raises(requests.HTTPError):
        api_client.fetch_response("CVE-2099-10001")


# --- CLI Integration Tests ---


def test_cli_local_input_success(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(main.student, "VARIANT_NUMBER", 9)
    exit_code = main.main(["--cve", "CVE-2099-10001", "--input", str(SAMPLE_PATH)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["cve_id"] == "CVE-2099-10001"
    assert report["variant"] == 9
    assert report["decision"] == "other"


def test_cli_missing_file_returns_code_1(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(main.student, "VARIANT_NUMBER", 9)
    missing = tmp_path / "does_not_exist.json"
    exit_code = main.main(["--cve", "CVE-2099-10001", "--input", str(missing)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "File read error" in captured.err


def test_cli_invalid_json_returns_code_1(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(main.student, "VARIANT_NUMBER", 9)
    broken = tmp_path / "broken.json"
    broken.write_text("{invalid json", encoding="utf-8")
    exit_code = main.main(["--cve", "CVE-2099-10001", "--input", str(broken)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "Data format error" in captured.err


def test_cli_invalid_cve_format_exits_with_code_2() -> None:
    with pytest.raises(SystemExit) as exc_info:
        main.main(["--cve", "cve-2021-44228", "--input", str(SAMPLE_PATH)])
    assert exc_info.value.code == 2
