"""Throwaway SSH/SFTP (asyncssh) and FTP (pyftpdlib) servers for end-to-end tests.

Commands run through bash so the remote side behaves like a Linux box; a fake
`sudo` on PATH checks that the stored password arrives on stdin.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import threading
from pathlib import Path

import asyncssh
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

BASH = shutil.which("bash") or r"C:\Program Files\Git\bin\bash.exe"

FAKE_SUDO = r"""#!/usr/bin/env bash
# accepts: sudo -S -p '' sh -c CMD
while [ "${1#-}" != "$1" ]; do [ "$1" = "-p" ] && shift; shift; done
read -r pw
[ "$pw" = "$FAKE_SUDO_PASSWORD" ] || { echo "sudo: wrong password" >&2; exit 1; }
SUDO_OK=1 exec "$@"
"""


class _Server(asyncssh.SSHServer):
    def __init__(self, users: dict[str, str]) -> None:
        self.users = users

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return self.users.get(username) == password


def start_ssh(port: int, root: Path, users: dict[str, str], host_key: asyncssh.SSHKey,
              client_keys: list[asyncssh.SSHKey], sudo_password: str) -> "SSHHandle":
    bindir = root.parent / "fakebin"
    bindir.mkdir(exist_ok=True)
    (bindir / "sudo").write_text(FAKE_SUDO, newline="\n")

    async def handle(process: asyncssh.SSHServerProcess) -> None:
        env = dict(os.environ, FAKE_SUDO_PASSWORD=sudo_password)
        env["PATH"] = f"{bindir}{os.pathsep}{env['PATH']}"
        proc = await asyncio.create_subprocess_exec(
            BASH, "-c", f'export PATH="$(cygpath -u "{bindir}"):$PATH"; {process.command}',
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, env=env,
        )
        await process.redirect(stdin=proc.stdin, stdout=proc.stdout, stderr=proc.stderr)
        process.exit(await proc.wait())

    loop = asyncio.new_event_loop()
    ready = threading.Event()
    handle_ = SSHHandle(loop)

    def run() -> None:
        asyncio.set_event_loop(loop)
        handle_.server = loop.run_until_complete(asyncssh.create_server(
            lambda: _Server(users), "127.0.0.1", port,
            server_host_keys=[host_key],
            authorized_client_keys=asyncssh.import_authorized_keys(
                "".join(k.export_public_key().decode() for k in client_keys)) if client_keys else None,
            process_factory=handle,
            sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=str(root).encode()),
        ))
        ready.set()
        loop.run_forever()

    handle_.thread = threading.Thread(target=run, daemon=True)
    handle_.thread.start()
    ready.wait(10)
    return handle_


class SSHHandle:
    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop
        self.server = None
        self.thread: threading.Thread | None = None

    def stop(self) -> None:
        # Closing the listener is enough to free the port; live client
        # connections die with the loop.
        self.loop.call_soon_threadsafe(self.server.close)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(10)


def start_ftp(port: int, root: Path, user: str, password: str) -> FTPServer:
    auth = DummyAuthorizer()
    auth.add_user(user, password, str(root), perm="elradfmwMT")
    handler = type("H", (FTPHandler,), {"authorizer": auth, "banner": "test ftp ready"})
    server = FTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=server.serve_forever, kwargs={"timeout": 0.5}, daemon=True).start()
    return server
