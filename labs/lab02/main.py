import argparse
import json
import sys
from pathlib import Path
from time import sleep

from labs.lab02.task1 import Admin, User, UserAccount
from labs.lab02.task2 import audit_headers


def run_demo() -> None:
    print("=== 1. ДЕМОНСТРАЦІЯ СТВОРЕННЯ КОРИСТУВАЧА ТА ВХОДУ ===")
    user = User("alice", "alice@example.com")
    user.set_password("Secret123!")

    account = UserAccount(user=user)

    account.login("alice", "WrongPass", "192.168.1.50")
    print(f"Автентифікація після помилки: {account.is_authenticated()}")

    account.login("alice", "Secret123!", "192.168.1.50")
    print(f"Автентифікація успішна: {account.is_authenticated()}")

    print("\n=== 2. ВАЛІДАЦІЯ ЗМІНИ EMAIL ===")
    try:
        user.email = "bad_email_format"
    except ValueError as e:
        print(f"Успішно перехоплено помилку: {e}")

    user.email = "alice_new@corp.ua"
    print(f"Новий email: {user.email}")

    print("\n=== 3. ПЕРЕВІРКА ПРАВ АДМІНІСТРАТОРА ===")
    admin = Admin("admin_root", "root@corp.ua")
    admin.grant_permission("READ_CONFIDENTIAL")
    print(f"Має дозвіл READ_CONFIDENTIAL: {admin.has_permission('READ_CONFIDENTIAL')}")
    admin.revoke_permission("READ_CONFIDENTIAL")
    print(f"Після відкликання: {admin.has_permission('READ_CONFIDENTIAL')}")

    print("\n=== 4. ТАЙМАУТ ТА ВИХІД ===")
    if account["session"]:
        print(
            f"Сесія активна (таймаут 1с): {account['session'].is_active(timeout_sec=1)}"
        )
        sleep(1.1)
        print(
            f"Сесія після паузи (таймаут 1с): {account['session'].is_active(timeout_sec=1)}"
        )

    account.logout()
    print(f"Статус після logout: {account.is_authenticated()}")

    print("\n=== 5. ЗАПИСИ ЖУРНАЛУ АУДИТУ ===")
    account["audit_log"].show_all()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Консольна утиліта кібербезпеки (Лабораторна робота №2)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("demo", help="Запустити демонстрацію класів ООП")

    analyze_parser = subparsers.add_parser(
        "analyze", help="Аудит безпеки HTTP-заголовків відповідей"
    )
    analyze_parser.add_argument(
        "--headers-file",
        type=Path,
        required=True,
        help="Шлях до файлу з HTTP-заголовками (.json)",
    )
    analyze_parser.add_argument(
        "--output-csv",
        type=Path,
        default=Path("labs/lab02/data/headers_audit.csv"),
        help="Шлях для збереження підсумкового CSV-звіту",
    )
    analyze_parser.add_argument(
        "--strict",
        action="store_true",
        help="Увімкнути суворий режим аудиту",
    )
    analyze_parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Рівень деталізації логування",
    )

    args = parser.parse_args()

    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        try:
            audit_headers(
                headers_file=args.headers_file,
                output_csv=args.output_csv,
                strict=args.strict,
                log_level=args.log_level,
            )
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"Помилка під час аналізу: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
