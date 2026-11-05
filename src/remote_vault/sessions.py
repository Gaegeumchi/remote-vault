"""Live SSH/SFTP and FTP sessions, pooled per connection name."""

from __future__ import annotations

import ftplib
import io
import os
import posixpath
import shlex
import stat
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import paramiko

from .store import Profile, Store

MAX_OUTPUT = 100_000  # bytes kept per stream for exec output
MAX_READ = 1_000_000  # bytes for read_file


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def resolve_local(path: str) -> Path:
    return Path(path).expanduser().resolve()


class RemoteSession:
    """Common surface. Paths given to methods are already resolved."""

    profile: Profile

    def resolve(self, path: str | None) -> str:
        base = self.profile.default_dir
        if not path:
            return base or "."
        if path.startswith("/") or not base:
            return path
        return posixpath.join(base, path)

    def alive(self) -> bool:  # pragma: no cover - overridden
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError


# --------------------------------------------------------------------------
# SSH / SFTP
# --------------------------------------------------------------------------
class SSHSession(RemoteSession):
    def __init__(self, profile: Profile, secrets: dict[str, str], home: Path) -> None:
        self.profile = profile
        self._secrets = secrets
        self._sftp: paramiko.SFTPClient | None = None
        self._sftp_lock = threading.Lock()

        known_hosts = home / "known_hosts"
        known_hosts.touch(exist_ok=True)
        client = paramiko.SSHClient()
        try:
            client.load_system_host_keys()
        except OSError:
            pass
        client.load_host_keys(str(known_hosts))
        # Trust on first use: unknown hosts are recorded in <home>/known_hosts;
        # a changed key afterwards raises BadHostKeyException and is refused.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        password = secrets.get("password")
        client.connect(
            hostname=profile.host,
            port=profile.port,
            username=profile.username,
            password=password,
            key_filename=profile.key_path,
            passphrase=secrets.get("passphrase"),
            allow_agent=True,
            look_for_keys=not (password or profile.key_path),
            timeout=15,
            banner_timeout=15,
            auth_timeout=20,
        )
        transport = client.get_transport()
        assert transport is not None
        transport.set_keepalive(30)
        self.client = client

    def alive(self) -> bool:
        t = self.client.get_transport()
        return bool(t and t.is_active())

    def close(self) -> None:
        try:
            if self._sftp:
                self._sftp.close()
        finally:
            self.client.close()

    @property
    def sftp(self) -> paramiko.SFTPClient:
        if self._sftp is None:
            self._sftp = self.client.open_sftp()
        return self._sftp

    # ---- exec -----------------------------------------------------------
    def exec(
        self,
        command: str,
        *,
        cwd: str | None = None,
        timeout: float = 120,
        stdin: str | None = None,
        sudo: bool = False,
        pty: bool = False,
    ) -> dict:
        workdir = cwd or self.profile.default_dir
        full = command
        if sudo:
            password = self._secrets.get("password")
            if not password:
                raise ValueError("sudo=True needs a stored password for this connection")
            full = f"sudo -S -p '' sh -c {shlex.quote(command)}"
        if workdir:
            full = f"cd {shlex.quote(workdir)} && {full}"

        transport = self.client.get_transport()
        assert transport is not None
        chan = transport.open_session()
        if pty:
            chan.get_pty(width=200, height=50)
        chan.exec_command(full)
        if sudo:
            chan.sendall((self._secrets["password"] + "\n").encode())
        if stdin is not None:
            chan.sendall(stdin.encode())
        if sudo or stdin is not None:
            chan.shutdown_write()

        out, err = bytearray(), bytearray()
        out_total = err_total = 0
        deadline = time.monotonic() + timeout
        timed_out = False
        start = time.monotonic()
        while True:
            busy = False
            if chan.recv_ready():
                chunk = chan.recv(65536)
                out_total += len(chunk)
                if len(out) < MAX_OUTPUT:
                    out += chunk[: MAX_OUTPUT - len(out)]
                busy = True
            if chan.recv_stderr_ready():
                chunk = chan.recv_stderr(65536)
                err_total += len(chunk)
                if len(err) < MAX_OUTPUT:
                    err += chunk[: MAX_OUTPUT - len(err)]
                busy = True
            if not busy:
                if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                    break
                if time.monotonic() > deadline:
                    timed_out = True
                    break
                time.sleep(0.02)
        exit_code = chan.recv_exit_status() if not timed_out else None
        chan.close()

        def scrub(raw: bytearray) -> str:
            text = raw.decode("utf-8", errors="replace")
            secret = self._secrets.get("password")
            # A pty echoes stdin, so a sudo password could otherwise show up.
            return text.replace(secret, "********") if secret else text

        result: dict = {
            "exit_code": exit_code,
            "stdout": scrub(out),
            "stderr": scrub(err),
            "duration_s": round(time.monotonic() - start, 3),
        }
        if timed_out:
            result["timed_out"] = True
            result["note"] = f"command exceeded {timeout}s; channel closed (process may keep running remotely)"
        if out_total > MAX_OUTPUT:
            result["stdout_truncated_bytes"] = out_total - MAX_OUTPUT
        if err_total > MAX_OUTPUT:
            result["stderr_truncated_bytes"] = err_total - MAX_OUTPUT
        return result

    # ---- files ----------------------------------------------------------
    def _is_dir(self, path: str) -> bool:
        try:
            return stat.S_ISDIR(self.sftp.stat(path).st_mode or 0)
        except FileNotFoundError:
            return False

    def _exists(self, path: str) -> bool:
        try:
            self.sftp.stat(path)
            return True
        except FileNotFoundError:
            return False

    def list_dir(self, path: str) -> list[dict]:
        with self._sftp_lock:
            entries = []
            for a in self.sftp.listdir_attr(path):
                mode = a.st_mode or 0
                entries.append({
                    "name": a.filename,
                    "type": "dir" if stat.S_ISDIR(mode) else "link" if stat.S_ISLNK(mode) else "file",
                    "size": a.st_size,
                    "modified": _iso(a.st_mtime),
                    "mode": stat.filemode(mode),
                })
            return sorted(entries, key=lambda e: (e["type"] != "dir", e["name"]))

    def mkdir(self, path: str) -> None:
        with self._sftp_lock:
            self._mkdir_p(path)

    def _mkdir_p(self, path: str) -> None:
        if not path or path in ("/", ".") or self._is_dir(path):
            return
        self._mkdir_p(posixpath.dirname(path.rstrip("/")))
        self.sftp.mkdir(path)

    def upload(self, local: Path, remote: str, overwrite: bool) -> dict:
        with self._sftp_lock:
            if self._is_dir(remote) and local.is_file():
                remote = posixpath.join(remote, local.name)
            files = total = 0
            if local.is_dir():
                for root, _dirs, names in os.walk(local):
                    rel = Path(root).relative_to(local).as_posix()
                    target_dir = remote if rel == "." else posixpath.join(remote, rel)
                    self._mkdir_p(target_dir)
                    for n in names:
                        target = posixpath.join(target_dir, n)
                        if not overwrite and self._exists(target):
                            raise FileExistsError(f"remote file exists: {target}")
                        self.sftp.put(str(Path(root) / n), target)
                        files += 1
                        total += (Path(root) / n).stat().st_size
            else:
                if not overwrite and self._exists(remote):
                    raise FileExistsError(f"remote file exists: {remote}")
                self._mkdir_p(posixpath.dirname(remote))
                self.sftp.put(str(local), remote)
                files, total = 1, local.stat().st_size
            return {"remote_path": remote, "files": files, "bytes": total}

    def download(self, remote: str, local: Path, overwrite: bool) -> dict:
        with self._sftp_lock:
            if self._is_dir(remote):
                counts = [0, 0]
                self._download_dir(remote, local, overwrite, counts)
                return {"local_path": str(local), "files": counts[0], "bytes": counts[1]}
            if local.is_dir():
                local = local / posixpath.basename(remote)
            if local.exists() and not overwrite:
                raise FileExistsError(f"local file exists: {local}")
            local.parent.mkdir(parents=True, exist_ok=True)
            self.sftp.get(remote, str(local))
            return {"local_path": str(local), "files": 1, "bytes": local.stat().st_size}

    def _download_dir(self, remote: str, local: Path, overwrite: bool, counts: list[int]) -> None:
        local.mkdir(parents=True, exist_ok=True)
        for a in self.sftp.listdir_attr(remote):
            src = posixpath.join(remote, a.filename)
            dst = local / a.filename
            if stat.S_ISDIR(a.st_mode or 0):
                self._download_dir(src, dst, overwrite, counts)
            else:
                if dst.exists() and not overwrite:
                    raise FileExistsError(f"local file exists: {dst}")
                self.sftp.get(src, str(dst))
                counts[0] += 1
                counts[1] += a.st_size or 0

    def delete(self, path: str, recursive: bool) -> dict:
        with self._sftp_lock:
            if not self._is_dir(path):
                self.sftp.remove(path)
                return {"deleted": path, "files": 1}
            if not recursive:
                self.sftp.rmdir(path)  # only succeeds when empty
                return {"deleted": path, "files": 0}
            counts = [0]
            self._rm_tree(path, counts)
            return {"deleted": path, "files": counts[0]}

    def _rm_tree(self, path: str, counts: list[int]) -> None:
        for a in self.sftp.listdir_attr(path):
            child = posixpath.join(path, a.filename)
            if stat.S_ISDIR(a.st_mode or 0):
                self._rm_tree(child, counts)
            else:
                self.sftp.remove(child)
                counts[0] += 1
        self.sftp.rmdir(path)

    def rename(self, src: str, dst: str) -> None:
        with self._sftp_lock:
            try:
                self.sftp.posix_rename(src, dst)
            except (IOError, paramiko.SSHException):
                self.sftp.rename(src, dst)

    def read_file(self, path: str, max_bytes: int) -> bytes:
        with self._sftp_lock, self.sftp.open(path, "rb") as f:
            return f.read(max_bytes + 1)

    def write_file(self, path: str, data: bytes, append: bool) -> None:
        with self._sftp_lock:
            self._mkdir_p(posixpath.dirname(path))
            with self.sftp.open(path, "ab" if append else "wb") as f:
                f.write(data)


# --------------------------------------------------------------------------
# FTP / FTPS
# --------------------------------------------------------------------------
class FTPSession(RemoteSession):
    def __init__(self, profile: Profile, secrets: dict[str, str]) -> None:
        self.profile = profile
        self._lock = threading.Lock()
        ftp: ftplib.FTP = ftplib.FTP_TLS(timeout=30) if profile.protocol == "ftps" else ftplib.FTP(timeout=30)
        ftp.encoding = "utf-8"
        ftp.connect(profile.host, profile.port)
        ftp.login(profile.username, secrets.get("password", ""))
        if isinstance(ftp, ftplib.FTP_TLS):
            ftp.prot_p()
        ftp.set_pasv(True)
        self.ftp = ftp

    def alive(self) -> bool:
        try:
            with self._lock:
                self.ftp.voidcmd("NOOP")
            return True
        except (ftplib.all_errors):
            return False

    def close(self) -> None:
        try:
            self.ftp.quit()
        except ftplib.all_errors:
            self.ftp.close()

    def exec(self, *_a, **_k) -> dict:
        raise ValueError("command execution is not available over FTP; use an ssh connection")

    def _is_dir(self, path: str) -> bool:
        cur = self.ftp.pwd()
        try:
            self.ftp.cwd(path)
            return True
        except ftplib.error_perm:
            return False
        finally:
            self.ftp.cwd(cur)

    def _exists(self, path: str) -> bool:
        if self._is_dir(path):
            return True
        try:
            self.ftp.size(path)
            return True
        except ftplib.error_perm:
            return False

    def _entries(self, path: str) -> list[dict]:
        try:
            out = []
            for name, facts in self.ftp.mlsd(path, facts=["type", "size", "modify"]):
                if name in (".", "..") or facts.get("type") in ("cdir", "pdir"):
                    continue
                mod = facts.get("modify")
                out.append({
                    "name": name,
                    "type": "dir" if facts.get("type") == "dir" else "file",
                    "size": int(facts["size"]) if "size" in facts else None,
                    "modified": (
                        datetime.strptime(mod[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).isoformat()
                        if mod else None
                    ),
                })
            return out
        except ftplib.error_perm:
            # Server without MLSD: fall back to names + directory probe.
            out = []
            for full in self.ftp.nlst(path):
                name = posixpath.basename(full.rstrip("/"))
                if name in (".", ".."):
                    continue
                child = posixpath.join(path, name)
                out.append({"name": name, "type": "dir" if self._is_dir(child) else "file",
                            "size": None, "modified": None})
            return out

    def list_dir(self, path: str) -> list[dict]:
        with self._lock:
            return sorted(self._entries(path), key=lambda e: (e["type"] != "dir", e["name"]))

    def mkdir(self, path: str) -> None:
        with self._lock:
            self._mkdir_p(path)

    def _mkdir_p(self, path: str) -> None:
        if not path or path in ("/", ".") or self._is_dir(path):
            return
        self._mkdir_p(posixpath.dirname(path.rstrip("/")))
        self.ftp.mkd(path)

    def _put(self, local: Path, remote: str, overwrite: bool) -> int:
        if not overwrite and self._exists(remote):
            raise FileExistsError(f"remote file exists: {remote}")
        with open(local, "rb") as f:
            self.ftp.storbinary(f"STOR {remote}", f)
        return local.stat().st_size

    def upload(self, local: Path, remote: str, overwrite: bool) -> dict:
        with self._lock:
            if local.is_file() and self._is_dir(remote):
                remote = posixpath.join(remote, local.name)
            files = total = 0
            if local.is_dir():
                for root, _dirs, names in os.walk(local):
                    rel = Path(root).relative_to(local).as_posix()
                    target_dir = remote if rel == "." else posixpath.join(remote, rel)
                    self._mkdir_p(target_dir)
                    for n in names:
                        total += self._put(Path(root) / n, posixpath.join(target_dir, n), overwrite)
                        files += 1
            else:
                self._mkdir_p(posixpath.dirname(remote))
                total, files = self._put(local, remote, overwrite), 1
            return {"remote_path": remote, "files": files, "bytes": total}

    def _get(self, remote: str, local: Path, overwrite: bool) -> int:
        if local.exists() and not overwrite:
            raise FileExistsError(f"local file exists: {local}")
        local.parent.mkdir(parents=True, exist_ok=True)
        with open(local, "wb") as f:
            self.ftp.retrbinary(f"RETR {remote}", f.write)
        return local.stat().st_size

    def download(self, remote: str, local: Path, overwrite: bool) -> dict:
        with self._lock:
            if self._is_dir(remote):
                counts = [0, 0]
                self._download_dir(remote, local, overwrite, counts)
                return {"local_path": str(local), "files": counts[0], "bytes": counts[1]}
            if local.is_dir():
                local = local / posixpath.basename(remote)
            return {"local_path": str(local), "files": 1, "bytes": self._get(remote, local, overwrite)}

    def _download_dir(self, remote: str, local: Path, overwrite: bool, counts: list[int]) -> None:
        local.mkdir(parents=True, exist_ok=True)
        for e in self._entries(remote):
            src = posixpath.join(remote, e["name"])
            if e["type"] == "dir":
                self._download_dir(src, local / e["name"], overwrite, counts)
            else:
                counts[1] += self._get(src, local / e["name"], overwrite)
                counts[0] += 1

    def delete(self, path: str, recursive: bool) -> dict:
        with self._lock:
            if not self._is_dir(path):
                self.ftp.delete(path)
                return {"deleted": path, "files": 1}
            if not recursive:
                self.ftp.rmd(path)
                return {"deleted": path, "files": 0}
            counts = [0]
            self._rm_tree(path, counts)
            return {"deleted": path, "files": counts[0]}

    def _rm_tree(self, path: str, counts: list[int]) -> None:
        for e in self._entries(path):
            child = posixpath.join(path, e["name"])
            if e["type"] == "dir":
                self._rm_tree(child, counts)
            else:
                self.ftp.delete(child)
                counts[0] += 1
        self.ftp.rmd(path)

    def rename(self, src: str, dst: str) -> None:
        with self._lock:
            self.ftp.rename(src, dst)

    def read_file(self, path: str, max_bytes: int) -> bytes:
        with self._lock:
            buf = io.BytesIO()

            def sink(chunk: bytes) -> None:
                # Aborting mid-transfer leaves many servers' control channel
                # out of sync, so let it finish and just stop keeping bytes.
                room = max_bytes + 1 - buf.tell()
                if room > 0:
                    buf.write(chunk[:room])

            self.ftp.retrbinary(f"RETR {path}", sink)
            return buf.getvalue()

    def write_file(self, path: str, data: bytes, append: bool) -> None:
        with self._lock:
            self._mkdir_p(posixpath.dirname(path))
            self.ftp.storbinary(f"{'APPE' if append else 'STOR'} {path}", io.BytesIO(data))


# --------------------------------------------------------------------------
# Pool
# --------------------------------------------------------------------------
class SessionPool:
    def __init__(self, store: Store) -> None:
        self.store = store
        self._sessions: dict[str, RemoteSession] = {}
        self._lock = threading.Lock()
        self._name_locks: dict[str, threading.Lock] = {}

    def open(self, profile: Profile) -> RemoteSession:
        secrets = self.store.get_secrets(profile.name)
        if profile.protocol == "ssh":
            return SSHSession(profile, secrets, self.store.home)
        return FTPSession(profile, secrets)

    def get(self, name: str) -> RemoteSession:
        profile = self.store.get(name)
        with self._lock:
            name_lock = self._name_locks.setdefault(name, threading.Lock())
        with name_lock:
            sess = self._sessions.get(name)
            if sess is not None and sess.alive():
                return sess
            if sess is not None:
                sess.close()
            sess = self.open(profile)
            self._sessions[name] = sess
            return sess

    def drop(self, name: str) -> bool:
        sess = self._sessions.pop(name, None)
        if sess is not None:
            try:
                sess.close()
            except Exception:
                pass
            return True
        return False

    def close_all(self) -> None:
        for name in list(self._sessions):
            self.drop(name)
