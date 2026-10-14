import argparse
import csv
import json
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path

VERSION_PATTERN = re.compile(r"\d+(?:\.\d+)+")

CRITICAL_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
)

STRICT_ADDITIONAL_HEADERS = (
    "Referrer-Policy",
    "Permissions-Policy",
)

logger = logging.getLogger("HTTPHeaderAuditor")


@dataclass
class AuditResult:
    url: str
    score: int
    grade: str
    status: str
    missing_headers: list[str]
    leak_alerts: list[str]


def parse_response_headers_json(file_path: Path) -> dict[str, dict[str, str]]:
    if not file_path.exists():
        raise FileNotFoundError(f"Файл вхідних даних не знайдено: {file_path}")

    with file_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    urls_data: dict[str, dict[str, str]] = {}

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                url = item.get("url", "unknown_url")
                headers = item.get("headers", {})
                urls_data[url] = {str(k): str(v) for k, v in headers.items()}
    else:
        raise TypeError("Вхідні дані не відповідають умові функції")

    return urls_data


def calculate_security_score(
    headers: dict[str, str], strict: bool
) -> tuple[int, str, str, list[str]]:
    headers_lower = {k.lower(): v for k, v in headers.items()}
    missing: list[str] = []

    weights: dict[str, int] = {
        "content-security-policy": 30,
        "strict-transport-security": 25,
        "x-frame-options": 20,
        "x-content-type-options": 20,
    }

    score = 100

    for header in CRITICAL_HEADERS:
        if header.lower() not in headers_lower:
            missing.append(header)
            score -= weights.get(header.lower(), 20)

    if strict:
        for header in STRICT_ADDITIONAL_HEADERS:
            if header.lower() not in headers_lower:
                missing.append(header)
                score -= 10

    if "x-powered-by" in headers_lower:
        score -= 10
    if "server" in headers_lower and VERSION_PATTERN.search(headers_lower["server"]):
        score -= 5

    score = max(0, min(100, score))

    if score >= 90:
        grade = "A+"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"

    pass_threshold = 85 if strict else 80
    if score >= pass_threshold:
        status = "PASS"
    elif score >= 50:
        status = "WARN"
    else:
        status = "FAIL"

    return score, grade, status, missing


def check_software_leaks(url: str, headers: dict[str, str]) -> list[str]:
    leaks: list[str] = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    server_val = headers_lower.get("server")
    if server_val and VERSION_PATTERN.search(server_val):
        leaks.append(f"[LEAK] {url} leaks version in 'Server': {server_val}")

    powered_by_val = headers_lower.get("x-powered-by")
    if powered_by_val:
        leaks.append(
            f"[LEAK] {url} leaks tech stack in 'X-Powered-By': {powered_by_val}"
        )

    return leaks


def save_report_to_csv(results: list[AuditResult], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "Target Resource",
                "Security Score",
                "Grade",
                "Status",
                "Missing Security Headers",
                "Software Leaks",
            ]
        )
        for r in results:
            writer.writerow(
                [
                    r.url,
                    f"{r.score}/100",
                    r.grade,
                    r.status,
                    ", ".join(r.missing_headers) if r.missing_headers else "None",
                    "; ".join(r.leak_alerts) if r.leak_alerts else "None",
                ]
            )


def audit_headers(
    headers_file: Path,
    output_csv: Path,
    strict: bool = False,
    log_level: str = "INFO",
) -> list[AuditResult]:
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="[%(levelname)s] %(message)s",
    )

    logger.info("Auditing HTTP response headers from %s...", headers_file)

    urls_data = parse_response_headers_json(headers_file)
    results: list[AuditResult] = []
    all_leaks: list[str] = []

    for url, headers in urls_data.items():
        score, grade, status, missing = calculate_security_score(headers, strict)
        leaks = check_software_leaks(url, headers)

        if missing:
            logger.warning(
                "Resource '%s' missing security headers: %s",
                url,
                ", ".join(missing),
            )

        res = AuditResult(
            url=url,
            score=score,
            grade=grade,
            status=status,
            missing_headers=missing,
            leak_alerts=leaks,
        )
        results.append(res)
        all_leaks.extend(leaks)

    print()
    print(
        f"{'Target Resource':<35} {'Security Score':<16} {'Status':<8} {'Missing Security Headers'}"
    )
    print("-" * 90)
    for r in results:
        score_str = f"{r.score}/100 ({r.grade})"
        missing_str = ", ".join(r.missing_headers) if r.missing_headers else "None"
        print(f"{r.url:<35} {score_str:<16} {r.status:<8} {missing_str}")

    if all_leaks:
        print("\n=== Server Software Leak Alerts ===")
        for alert in all_leaks:
            print(alert)

    save_report_to_csv(results, output_csv)
    print()
    logger.info("Header audit report generated at %s", output_csv)

    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Аудитор безпеки HTTP-заголовків відповідей (Варіант 9)"
    )
    parser.add_argument(
        "--headers-file",
        type=Path,
        required=True,
        help="Шлях до вхідного JSON-файлу з HTTP-заголовками",
    )
    parser.add_argument(
        "--output-csv",
        type=Path,
        default=Path("data/headers_audit.csv"),
        help="Шлях до вихідного CSV-звіту",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Суворий режим перевірки додаткових заголовків",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Рівень логування (типово: INFO)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        audit_headers(
            headers_file=args.headers_file,
            output_csv=args.output_csv,
            strict=args.strict,
            log_level=args.log_level,
        )
    except (OSError, ValueError, json.JSONDecodeError) as e:
        logger.error("Помилка виконання аудиту: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
