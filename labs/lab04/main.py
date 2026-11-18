from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import requests

from labs.lab04 import analysis, api_client
from shared import student

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def load_response(path: str | Path) -> Any:
    raw_text = Path(path).read_text(encoding="utf-8")
    return json.loads(raw_text)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fetch or inspect an NVD CVE record and evaluate a CVSS rule."
    )
    parser.add_argument(
        "--cve",
        required=True,
        help="CVE identifier matching CVE-YYYY-NNNN+ (case-sensitive).",
    )
    parser.add_argument(
        "--input",
        default=None,
        help="Optional path to a local NVD JSON file instead of querying the API.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    variant = getattr(student, "VARIANT_NUMBER", None)
    if (
        isinstance(variant, bool)
        or not isinstance(variant, int)
        or not (1 <= variant <= 15)
    ):
        print(
            "Error: VARIANT_NUMBER in shared.student must be an integer from 1 to 15.",
            file=sys.stderr,
        )
        return 2

    parser = _build_parser()
    args = parser.parse_args(argv)

    if CVE_PATTERN.fullmatch(args.cve) is None:
        parser.error(
            f"invalid --cve value '{args.cve}': expected format CVE-YYYY-NNNN+"
        )

    try:
        if args.input is not None:
            payload = load_response(args.input)
        else:
            payload = api_client.fetch_response(args.cve)

        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, variant)
    except (OSError, UnicodeDecodeError) as err:
        print(f"File read error: {err.strerror or err}", file=sys.stderr)
        return 1
    except (json.JSONDecodeError, requests.exceptions.JSONDecodeError):
        print(
            "Data format error: failed to decode response as valid JSON.",
            file=sys.stderr,
        )
        return 1
    except requests.exceptions.Timeout:
        print("Network error: request to NVD API timed out.", file=sys.stderr)
        return 1
    except requests.exceptions.HTTPError as err:
        status = err.response.status_code if err.response is not None else "unknown"
        print(f"HTTP error: NVD API returned status {status}.", file=sys.stderr)
        return 1
    except requests.exceptions.RequestException:
        print("Network error: failed to communicate with NVD API.", file=sys.stderr)
        return 1
    except ValueError as err:
        print(f"Validation error: {err}", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
