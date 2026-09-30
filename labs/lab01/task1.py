import os
import random
import string
import sys

import tabulate

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

passwords = [
    "Digital@F0r3nsics",
    "plain",
    "Encrypt10n@Key",
    "member",
    "Security@Audit2023",
    "regular",
    "Hack3r@D3fense",
    "ordinary",
    "Threat@Intel",
    "usual",
]
criteria = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
forbidden_passwords = {"plain", "member", "regular", "ordinary", "usual", "user"}
random_i = [random.randint(0, len(passwords) - 1) for _ in range(3)]
results = []

def create_duplicates():
    duplicates = []
    all_passwords = passwords
    for i in random_i:
        duplicate = passwords[i]
        duplicates.append(duplicate)
        all_passwords.append(duplicate)
    print(f"Дупліковані паролі:{duplicates}")
    return all_passwords

def create_results(passwords):
    for p in passwords:
            has_digit = any(x.isdigit for x in p)
            has_upper = any(x.isupper for x in p)
            has_special = any(x in string.punctuation for x in p)
            total_criterias = sum([has_digit, has_upper, has_special])
            if p in forbidden_passwords or len(p) < criteria["min_length"]:
                s = "Заборонений"
            elif (
                len(p) > criteria["min_length"] + 3
                and total_criterias == 3
                and passwords.count(p) == 1
            ):
                s = "Дуже сильний"
            elif total_criterias == 3:
                s = "Сильний"
            elif total_criterias == 2:
                s = "Середній"
            elif total_criterias == 1:
                s = "Слабкий"
            else:
                print("Щось пішло не так")
            results.append((p, s))
    return results

def print_results(results):
    print(
            tabulate.tabulate(
                results,
                headers=["Пароль", "Статус"],
                showindex=range(1, len(results) + 1),
                tablefmt="grid",
            )
        )

def main() -> None:
    print(GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER)
    all_passwords = create_duplicates()
    print(all_passwords)
    results = create_results(all_passwords)
    print_results(results)
    


if __name__ == "__main__":
    main()
