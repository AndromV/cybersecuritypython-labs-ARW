import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(BASE_DIR, "../../"))
sys.path.append(PROJECT_DIR)
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER
from task1 import main as run_task1
from task2 import main as run_task2
from task3 import main as run_task3

def task_title(title) -> None:
    print("\n" + "=" * 60)
    print(f" {title} ".center(60, "="))
    print("=" * 60 + "\n")

def main() -> None:
    task_title("Лабораторна робота №1")
    print(STUDENT_NAME)
    print(GROUP_NAME)
    print(VARIANT_NUMBER)

    task_title("Завдання 1")
    run_task1()

    task_title("Завдання 2")
    run_task2()

    task_title("Завдання 3")
    run_task3()

if __name__ == "__main__":
    main()