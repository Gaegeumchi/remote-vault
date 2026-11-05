"""MCP server exposing stored SSH/SFTP/FTP connections as tools.

Agents refer to a connection by name; hosts, users, passwords and key
passphrases are resolved here and never sent back to the agent.
"""

from __future__ import annotations

import functools
import os
from typing import Any, Callable, Literal

import anyio.to_thread
import paramiko
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from .sessions import MAX_READ, SessionPool, SSHSession, resolve_local
from .store import Profile, Store

INSTRUCTIONS = """\
Run shell commands and move files on remote machines over SSH/SFTP/FTP using
stored connections. Credentials are managed by this server: call
list_connections to see the available connection names, then pass `connection`
to the other tools. You never need (and cannot read) passwords or keys.
Remote relative paths resolve against the connection's default_dir.
Local paths are on the machine running this server; prefer absolute paths.
FTP connections support file tools only, not run_command.
"""

store = Store()
pool = SessionPool(store)
mcp = MCPServer("remote-vault", instructions=INSTRUCTIONS)
READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=True)
DESTRUCTIVE = ToolAnnotations(destructive_hint=True, open_world_hint=True)
CONFIG_LOCKED = os.environ.get("REMOTE_VAULT_LOCK_CONFIG", "").lower() in ("1", "true", "yes")


def _describe(exc: BaseException) -> str:
    if isinstance(exc, paramiko.BadHostKeyException):
        return (f"host key for {exc.hostname} has CHANGED since first connect; refusing to connect "
                f"(possible MITM). If the change is expected, the user can run "
                f"`remote-vault forget-host {exc.hostname}`.")
    if isinstance(exc, paramiko.AuthenticationException):
        return (f"authentication failed: {exc}. Ask the user to update the stored credentials "
                f"(`remote-vault edit <name> --password`).")
    if isinstance(exc, KeyError) and exc.args:
        return str(exc.args[0])
    return f"{type(exc).__name__}: {exc}"


async def _run(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    # paramiko/ftplib are blocking; keep the event loop free. Errors are turned
    # into ToolError so the agent sees the message instead of a generic failure.
    try:
        return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))
    except ToolError:
        raise
    except Exception as exc:
        raise ToolError(_describe(exc)) from exc


# --------------------------------------------------------------------------
# Connection management
# --------------------------------------------------------------------------
@mcp.tool(annotations=READ_ONLY)
async def list_connections() -> list[dict]:
    """List stored connections (name, protocol, host, user, default_dir, auth type). No secrets."""
    return [p.public_view(store) for p in store.list()]


@mcp.tool(annotations=READ_ONLY)
async def test_connection(connection: str) -> dict:
    """Open a fresh connection and report basic info about the remote side."""

    def work() -> dict:
        pool.drop(connection)
        sess = pool.get(connection)
        info: dict = {"connection": connection, "ok": True, "protocol": sess.profile.protocol}
        if isinstance(sess, SSHSession):
            t = sess.client.get_transport()
            info["server_version"] = t.remote_version if t else None
            info["home"] = sess.sftp.normalize(".")
        else:
            info["welcome"] = sess.ftp.getwelcome()
            info["cwd"] = sess.ftp.pwd()
        return info

    return await _run(work)


@mcp.tool()
async def disconnect(connection: str) -> dict:
    """Close the pooled session for a connection (it reconnects on next use)."""
    return {"closed": pool.drop(connection)}


if not CONFIG_LOCKED:

    @mcp.tool()
    async def add_connection(
        name: str,
        protocol: Literal["ssh", "sftp", "ftp", "ftps"],
        host: str,
        username: str,
        port: int = 0,
        password: str | None = None,
        key_path: str | None = None,
        passphrase: str | None = None,
        default_dir: str | None = None,
        description: str = "",
        overwrite: bool = False,
    ) -> dict:
        """Store a connection. Secrets go to the OS keyring and are never returned.

        protocol 'ssh' (or 'sftp') gives commands + file transfer; 'ftp'/'ftps' gives file transfer.
        port 0 means the protocol default. With overwrite=True, omitted secrets are kept.
        Prefer telling the user to run `remote-vault add <name>` so secrets never pass through chat.
        """
        def work() -> dict:
            profile = Profile(
                name=name, protocol=protocol, host=host, username=username, port=port,
                key_path=key_path, default_dir=default_dir, description=description,
            )
            store.put(profile, overwrite=overwrite)
            store.set_secrets(name, password=password, passphrase=passphrase)
            pool.drop(name)
            return {"saved": profile.public_view(store)}

        return await _run(work)

    @mcp.tool(annotations=DESTRUCTIVE)
    async def remove_connection(name: str) -> dict:
        """Delete a stored connection and its keyring secrets."""

        def work() -> dict:
            pool.drop(name)
            store.remove(name)
            return {"removed": name}

        return await _run(work)


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
@mcp.tool()
async def run_command(
    connection: str,
    command: str,
    cwd: str | None = None,
    timeout: float = 120,
    stdin: str | None = None,
    sudo: bool = False,
    pty: bool = False,
) -> dict:
    """Run a shell command over SSH and return exit_code, stdout, stderr.

    cwd defaults to the connection's default_dir. sudo=True runs the command via
    `sudo -S` and feeds the stored password automatically. pty=True allocates a
    terminal (for programs that insist on one). Output is capped at 100 KB per stream.
    """

    def work() -> dict:
        sess = pool.get(connection)
        if not isinstance(sess, SSHSession):
            raise ValueError(f"'{connection}' is an FTP connection; run_command needs ssh")
        return sess.exec(command, cwd=cwd, timeout=timeout, stdin=stdin, sudo=sudo, pty=pty)

    return await _run(work)


# --------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------
@mcp.tool(annotations=READ_ONLY)
async def list_dir(connection: str, path: str | None = None) -> dict:
    """List a remote directory (defaults to the connection's default_dir / login dir)."""

    def work() -> dict:
        sess = pool.get(connection)
        target = sess.resolve(path)
        return {"path": target, "entries": sess.list_dir(target)}

    return await _run(work)


@mcp.tool()
async def upload(connection: str, local_path: str, remote_path: str, overwrite: bool = True) -> dict:
    """Upload a local file or directory (recursively). Missing remote parent dirs are created.

    If remote_path is an existing directory, a file is placed inside it.
    """

    def work() -> dict:
        local = resolve_local(local_path)
        if not local.exists():
            raise FileNotFoundError(f"local path not found: {local}")
        sess = pool.get(connection)
        return sess.upload(local, sess.resolve(remote_path), overwrite)

    return await _run(work)


@mcp.tool()
async def download(connection: str, remote_path: str, local_path: str, overwrite: bool = True) -> dict:
    """Download a remote file or directory (recursively) to a local path.

    If local_path is an existing directory, a file is placed inside it.
    """

    def work() -> dict:
        sess = pool.get(connection)
        return sess.download(sess.resolve(remote_path), resolve_local(local_path), overwrite)

    return await _run(work)


@mcp.tool(annotations=READ_ONLY)
async def read_file(connection: str, path: str, max_bytes: int = 200_000, encoding: str = "utf-8") -> dict:
    """Read a remote text file and return its content (truncated to max_bytes, cap 1 MB)."""

    def work() -> dict:
        sess = pool.get(connection)
        target = sess.resolve(path)
        limit = max(1, min(max_bytes, MAX_READ))
        data = sess.read_file(target, limit)
        truncated = len(data) > limit
        data = data[:limit]
        if b"\x00" in data[:8192]:
            return {"path": target, "binary": True, "bytes_read": len(data),
                    "note": "binary file; use download instead"}
        return {"path": target, "content": data.decode(encoding, errors="replace"), "truncated": truncated}

    return await _run(work)


@mcp.tool()
async def write_file(connection: str, path: str, content: str, append: bool = False, encoding: str = "utf-8") -> dict:
    """Write (or append) text to a remote file, creating parent directories."""

    def work() -> dict:
        sess = pool.get(connection)
        target = sess.resolve(path)
        data = content.encode(encoding)
        sess.write_file(target, data, append)
        return {"path": target, "bytes": len(data), "appended": append}

    return await _run(work)


@mcp.tool()
async def make_dir(connection: str, path: str) -> dict:
    """Create a remote directory, including parents (like mkdir -p)."""

    def work() -> dict:
        sess = pool.get(connection)
        target = sess.resolve(path)
        sess.mkdir(target)
        return {"created": target}

    return await _run(work)


@mcp.tool(annotations=DESTRUCTIVE)
async def delete_path(connection: str, path: str, recursive: bool = False) -> dict:
    """Delete a remote file, or a directory (must be empty unless recursive=True)."""

    def work() -> dict:
        sess = pool.get(connection)
        target = sess.resolve(path)
        if target.rstrip("/") in ("", "/", "."):
            raise ValueError(f"refusing to delete '{target}'")
        return sess.delete(target, recursive)

    return await _run(work)


@mcp.tool()
async def move_path(connection: str, src: str, dst: str) -> dict:
    """Rename / move a remote file or directory."""

    def work() -> dict:
        sess = pool.get(connection)
        a, b = sess.resolve(src), sess.resolve(dst)
        sess.rename(a, b)
        return {"from": a, "to": b}

    return await _run(work)


def main() -> None:
    try:
        mcp.run()
    finally:
        pool.close_all()


if __name__ == "__main__":
    main()
