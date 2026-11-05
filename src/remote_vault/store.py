"""Connection profiles (plain JSON) + secrets (OS keyring).

Non-secret metadata lives in ``<home>/connections.json``. Passwords and key
passphrases go to the OS keyring (Windows Credential Manager, macOS Keychain,
Secret Service on Linux) and are never returned through the MCP tools.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

import keyring
import keyring.errors

PROTOCOLS = ("ssh", "ftp", "ftps")
DEFAULT_PORTS = {"ssh": 22, "ftp": 21, "ftps": 21}
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def home_dir() -> Path:
    path = Path(os.environ.get("REMOTE_VAULT_HOME", Path.home() / ".remote-vault"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def keyring_service() -> str:
    return os.environ.get("REMOTE_VAULT_KEYRING_SERVICE", "remote-vault")


@dataclass
class Profile:
    name: str
    protocol: str
    host: str
    username: str
    port: int = 0
    key_path: str | None = None
    default_dir: str | None = None
    description: str = ""
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not NAME_RE.match(self.name):
            raise ValueError(
                "name must be 1-64 chars of letters, digits, '.', '_' or '-' "
                "and start with a letter or digit"
            )
        self.protocol = self.protocol.lower()
        if self.protocol == "sftp":
            self.protocol = "ssh"
        if self.protocol not in PROTOCOLS:
            raise ValueError(f"protocol must be one of {PROTOCOLS} (or 'sftp')")
        if not self.host:
            raise ValueError("host is required")
        if not self.username:
            raise ValueError("username is required")
        if not self.port:
            self.port = DEFAULT_PORTS[self.protocol]
        if self.key_path:
            if self.protocol != "ssh":
                raise ValueError("key_path only applies to ssh connections")
            self.key_path = str(Path(self.key_path).expanduser())

    def public_view(self, store: "Store") -> dict:
        """Everything an agent may see: no secrets, only whether they exist."""
        data = asdict(self)
        secrets = store.get_secrets(self.name)
        data["has_password"] = bool(secrets.get("password"))
        data["has_passphrase"] = bool(secrets.get("passphrase"))
        data["auth"] = (
            "key" if self.key_path else "password" if data["has_password"] else "agent/default-keys"
        )
        return data


class Store:
    def __init__(self, home: Path | None = None) -> None:
        self.home = home or home_dir()
        self.path = self.home / "connections.json"

    # ---- profiles -------------------------------------------------------
    def _load(self) -> dict[str, dict]:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8")).get("connections", {})

    def _save(self, data: dict[str, dict]) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"connections": data}, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.path)

    def list(self) -> list[Profile]:
        return [Profile(**v) for _, v in sorted(self._load().items())]

    def get(self, name: str) -> Profile:
        data = self._load()
        if name not in data:
            known = ", ".join(sorted(data)) or "(none)"
            raise KeyError(f"unknown connection '{name}'. Known connections: {known}")
        return Profile(**data[name])

    def put(self, profile: Profile, *, overwrite: bool = False) -> None:
        data = self._load()
        if profile.name in data and not overwrite:
            raise ValueError(f"connection '{profile.name}' already exists (use overwrite/update)")
        data[profile.name] = asdict(profile)
        self._save(data)

    def remove(self, name: str) -> None:
        data = self._load()
        if name not in data:
            raise KeyError(f"unknown connection '{name}'")
        del data[name]
        self._save(data)
        self.delete_secrets(name)

    # ---- secrets --------------------------------------------------------
    def get_secrets(self, name: str) -> dict[str, str]:
        raw = keyring.get_password(keyring_service(), name)
        return json.loads(raw) if raw else {}

    def set_secrets(self, name: str, *, password: str | None = None, passphrase: str | None = None) -> None:
        """Merge new secrets into the keyring entry. Empty string clears a field."""
        secrets = self.get_secrets(name)
        for key, value in (("password", password), ("passphrase", passphrase)):
            if value is None:
                continue
            if value == "":
                secrets.pop(key, None)
            else:
                secrets[key] = value
        if secrets:
            keyring.set_password(keyring_service(), name, json.dumps(secrets))
        else:
            self.delete_secrets(name)

    def delete_secrets(self, name: str) -> None:
        try:
            keyring.delete_password(keyring_service(), name)
        except keyring.errors.PasswordDeleteError:
            pass
