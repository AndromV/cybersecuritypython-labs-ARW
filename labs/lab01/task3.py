from datetime import datetime
from functools import wraps
import os
import sys
import hashlib
import csv
import tabulate
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

users_to_register = (("Bob", "Digital@F0r3nsics"), ("Alex", "plain"), ("John", "Security@Audit2023"),
("Cockroach", "Hack3r@D3fense"), ("Cat", "qwerty"), ("Cookie", "Threat@Intel"), ("sky", "password"), 
("Pierser", "P!eRs@r"), ("UwU", "_26*6yha"), ("GitCraft", "10992737"))
salt = "00009"
filepath = "labs/lab01/data/users.csv"
log_path = "labs/lab01/data/log.json"
reading_users = []

class ValidationError(Exception):
    pass

def log_event(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        username = args[0] if args else "Unknown"
        status = "SUCCESS" if result else "FAILED"
        log_dic = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event": func.__name__,
            "username": username,
            "status": status,
        }

        folder = os.path.dirname(log_path)
        try:
            if folder:
                os.makedirs(folder, exist_ok = True)
            logs = []
            if os.path.exists(log_path):
                with open(log_path, mode = "r", encoding = "utf-8") as f:
                    logs = json.load(f)
                    logs = []
            logs.append(log_dic)
            with open(log_path, mode = "w", encoding = "utf-8") as f:
                json.dump(logs, f, indent = 4, ensure_ascii = False)
        except PermissionError:
            print(f"[Лог] Відмовлено в доступі до журналу '{log_path}'.")
        except (FileNotFoundError, IOError) as err:
            print(f"[Лог] Помилка запису логів: {err}")
        except json.JSONDecodeError:
            print(f"[Лог] Помилка формату JSON у '{log_path}'.")

        return result

    return wrapper

def generate_hash(password: str, salt: str) -> str:
    if password == None or salt == None:
        raise ValueError
    if len(password) < 13:
        raise ValidationError
    salt_password = password + salt
    password_b = salt_password.encode("utf-8")
    return hashlib.sha224(password_b).hexdigest()

def create_user(username, password, salt):
    sha_password = generate_hash(password, salt)
    return (username, sha_password)

def create_users(users_list, salt:str):
    valid_users = []
    for login, password in users_list:
        try:
            valid_users.append(create_user(login, password, salt))
        except ValidationError:
            print(f"Реєстрацію користувача {login} відхилено: пароль не містить допустиму кількість символів")
        except ValueError:
            print(f"Реєстрацію користувача {login} відхилено: помилка у хешуванні - відсутні пароль чи сіль")
    folder = os.path.dirname(filepath)
    try:
        if folder:
            os.makedirs(folder, exist_ok = True)
        with open(filepath, mode = "w", newline = "", encoding = "utf-8") as file:
            writer = csv.writer(file)
            for login, sha_password in valid_users:
                writer.writerow([login, sha_password])
    except PermissionError:
        print(f"[Помилка] Немає дозволу на запис у файл '{filepath}'.")
    except (FileNotFoundError, IOError) as err:
        print(f"[Помилка] Збій збереження файлу користувачів: {err}")

def read_users():
    try:
        with open(filepath, mode = "r", encoding = "utf-8") as file:
                for login, password in csv.reader(file):
                    reading_users.append((login, password))
    except FileNotFoundError:
        print(f"[Помилка] Файл '{filepath}' не знайдено.")
    except PermissionError:
        print(f"[Помилка] Немає прав для читання файлу '{filepath}'.")
    except IOError:
        print(f"[Помилка] Збій введення/виведення при зчитуванні файлу: IOError")

@log_event
def login(username: str, password:str) -> bool:
    try:
        if username == None or password == None:
                    raise ValueError
        check_hash = generate_hash(password, salt)
        if(username, check_hash) in reading_users:
            return True
        else:
            return False
    except ValidationError:
        print(f"Вхід користувача {username} відхилено: пароль не містить допустиму кількість символів")
        return False
    except ValueError:
        print(f"Вхід користувача {username} відхилено: помилка у хешуванні - відсутні пароль чи сіль")
        return False
    

def main() -> None:
    print(GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER)
    create_users(users_to_register, salt)
    read_users()
    print(
                    tabulate.tabulate(
                        reading_users,
                        headers = ["Логін", "Пароль"],
                        showindex = range(1, len(reading_users) + 1),
                        tablefmt = "grid",
                    )
                )
    print(login("Cockroach", "Hack3r@D3fense"))
if __name__ == "__main__":
    main()
