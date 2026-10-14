import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

PBKDF2_ITERATIONS: int = 100_000
SESSION_TIMEOUT_SEC: int = 900

EMAIL_REGEX = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9_]{2,63}@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$"
)


class User:
    def __init__(
        self,
        username: str,
        email: str,
        role: str = "user",
        active: bool = True,
    ) -> None:
        self.username = username
        self._email = ""
        self.email = email
        self.role = role
        self.active = active
        self.__password_hash: bytes | None = None
        self.__password_salt: bytes | None = None

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str) or not EMAIL_REGEX.match(value):
            raise ValueError(f"Некоректний формат email: '{value}'")
        self._email = value

    def set_password(self, password: str) -> None:
        if not password:
            raise ValueError("Пароль не може бути порожнім")
        salt = os.urandom(16)
        pwd_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PBKDF2_ITERATIONS,
        )
        self.__password_salt = salt
        self.__password_hash = pwd_hash

    def check_password(self, password: str) -> bool:
        if not self.__password_hash or not self.__password_salt:
            return False
        calc_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(self.__password_hash, calc_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__}(username='{self.username}', email='{self.email}', "
            f"role='{self.role}', active={self.active})"
        )


class Admin(User):
    def __init__(
        self,
        username: str,
        email: str,
        permissions: set[str] | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(username=username, email=email, role="admin", active=active)
        self.permissions: set[str] = (
            set(permissions) if permissions is not None else set()
        )

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        base_info = super().__str__()
        perms = ", ".join(self.permissions) if self.permissions else "none"
        return f"{base_info[:-1]}, permissions=[{perms}])"


class Session:
    def __init__(self, ip: str) -> None:
        self.ip = ip
        now = datetime.now(timezone.utc)
        self.login_time = now
        self.last_activity = now

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("Параметр timeout_sec має бути додатним числом")
        elapsed = datetime.now(timezone.utc) - self.last_activity
        return elapsed <= timedelta(seconds=timeout_sec)


@dataclass
class AuditRecord:
    timestamp: datetime
    username: str
    action: str


class AuditLog:
    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def add_log(self, username: str, action: str) -> None:
        self._records.append(
            AuditRecord(
                timestamp=datetime.now(timezone.utc),
                username=username,
                action=action,
            )
        )

    def show_all(self) -> None:
        if not self._records:
            print("  Журнал аудиту порожній.")
            return

        for entry in self._records:
            print(f"  [{entry.timestamp}] {entry.username} -> {entry.action}")


class UserAccount:
    ALLOWED_KEYS: ClassVar[set[str]] = {"user", "session", "audit_log"}

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.user = user
        self.session = session
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        if (
            self.user.username != username
            or not self.user.active
            or not self.user.check_password(password)
        ):
            self.audit_log.add_log(username, "login_failure")
            return False

        self.session = Session(ip=ip)
        self.session.touch()
        self.audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        if self.session is None:
            return False
        return self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        if self.session is not None:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key: str) -> Any:
        if key not in self.ALLOWED_KEYS:
            raise KeyError(f"Доступ заборонено або невідомий ключ: '{key}'")
        return getattr(self, key)

    def __setitem__(self, key: str, value: Any) -> None:
        if key not in self.ALLOWED_KEYS:
            raise KeyError(f"Не дозволено змінювати атрибут за ключем: '{key}'")

        if key == "user" and not isinstance(value, User):
            raise TypeError("Значення для 'user' повинно бути екземпляром User")
        if key == "session" and value is not None and not isinstance(value, Session):
            raise TypeError(
                "Значення для 'session' повинно бути екземпляром Session або None"
            )
        if key == "audit_log" and not isinstance(value, AuditLog):
            raise TypeError(
                "Значення для 'audit_log' повинно бути екземпляром AuditLog"
            )

        setattr(self, key, value)
