"""End-to-end: start local SSH + FTP servers, drive the real MCP server over stdio.

Run with:  uv run python tests/e2e.py
Uses a temp REMOTE_VAULT_HOME and a separate keyring service, cleaned up after.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

import asyncssh
import keyring
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

sys.path.insert(0, str(Path(__file__).parent))
import local_servers  # noqa: E402

SERVICE = "remote-vault-test"
SSH_PW = "s3cret-ssh-pw!"
FTP_PW = "ftp-pw-9876"
PASSPHRASE = "key-pass-phrase"
SECRETS = [SSH_PW, FTP_PW, PASSPHRASE]
results: list[tuple[str, bool, str]] = []


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def check(name: str, cond: bool, detail: str = "") -> None:
    results.append((name, bool(cond), detail))
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f"  -- {detail}" if detail and not cond else ""))


def posix(p: Path) -> str:
    return subprocess.run([local_servers.BASH, "-c", f'cygpath -u "{p}"'], capture_output=True, text=True).stdout.strip()


async def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="rv-e2e-"))
    home, ssh_root, ftp_root, local = (tmp / d for d in ("home", "sshroot", "ftproot", "local"))
    for d in (home, ssh_root, ftp_root, local):
        d.mkdir()
    (ssh_root / "site").mkdir()

    host_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    key_file = tmp / "id_test"
    client_key.write_private_key(str(key_file), passphrase=PASSPHRASE)

    ssh_port, ftp_port = free_port(), free_port()
    ssh = local_servers.start_ssh(ssh_port, ssh_root, {"alice": SSH_PW}, host_key, [client_key], SSH_PW)
    ftp = local_servers.start_ftp(ftp_port, ftp_root, "bob", FTP_PW)

    env = dict(os.environ, REMOTE_VAULT_HOME=str(home), REMOTE_VAULT_KEYRING_SERVICE=SERVICE)
    os.environ.update(REMOTE_VAULT_HOME=str(home), REMOTE_VAULT_KEYRING_SERVICE=SERVICE)

    # Human path: key-based profile added through the CLI (passphrase on stdin is not
    # possible with getpass, so write it via the store the CLI uses).
    from remote_vault.store import Profile, Store
    st = Store(home)
    st.put(Profile(name="box-key", protocol="ssh", host="127.0.0.1", port=ssh_port,
                   username="alice", key_path=str(key_file), default_dir="/site"))
    st.set_secrets("box-key", passphrase=PASSPHRASE)

    transcript: list[str] = []
    params = StdioServerParameters(command=sys.executable, args=["-m", "remote_vault.server"], env=env)
    try:
        async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
            await s.initialize()

            async def call(tool: str, **args):
                res = await s.call_tool(tool, args)
                text = "".join(getattr(c, "text", "") for c in res.content)
                transcript.append(text)
                if res.is_error:
                    return {"__error__": text}
                return res.structured_content.get("result", res.structured_content) if res.structured_content else json.loads(text)

            tools = {t.name for t in (await s.list_tools()).tools}
            check("tools registered", {"run_command", "upload", "download", "list_connections"} <= tools, str(tools))

            # Agent path: add connections through the tool.
            r1 = await call("add_connection", name="box", protocol="ssh", host="127.0.0.1",
                            port=ssh_port, username="alice", password=SSH_PW, description="test box")
            check("add ssh connection", "saved" in r1, str(r1))
            r2 = await call("add_connection", name="files", protocol="ftp", host="127.0.0.1",
                            port=ftp_port, username="bob", password=FTP_PW)
            check("add ftp connection", "saved" in r2, str(r2))
            dup = await call("add_connection", name="box", protocol="ssh", host="x", username="y")
            check("duplicate add refused", "__error__" in dup)

            conns = await call("list_connections")
            check("list_connections", sorted(c["name"] for c in conns) == ["box", "box-key", "files"], str(conns))
            check("auth types", {c["name"]: c["auth"] for c in conns} ==
                  {"box": "password", "box-key": "key", "files": "password"}, str(conns))

            t = await call("test_connection", connection="box")
            check("test_connection ssh (TOFU host key)", t.get("ok") is True, str(t))
            check("host key recorded", str(ssh_port) in (home / "known_hosts").read_text())
            t = await call("test_connection", connection="box-key")
            check("test_connection ssh key+passphrase", t.get("ok") is True, str(t))
            t = await call("test_connection", connection="files")
            check("test_connection ftp", t.get("ok") is True, str(t))

            # Commands
            r = await call("run_command", connection="box", command="echo hello; echo oops >&2; exit 3")
            check("run_command stdout/stderr/exit", r.get("stdout") == "hello\n" and r.get("stderr") == "oops\n"
                  and r.get("exit_code") == 3, str(r))
            r = await call("run_command", connection="box", command="pwd", cwd=posix(local))
            check("run_command cwd", r.get("stdout", "").strip() == posix(local), str(r))
            r = await call("run_command", connection="box", command="tr a-z A-Z", stdin="piped input")
            check("run_command stdin", r.get("stdout") == "PIPED INPUT", str(r))
            r = await call("run_command", connection="box", command='echo "sudo_ok=$SUDO_OK"', sudo=True)
            check("run_command sudo w/ stored password", r.get("stdout", "").strip() == "sudo_ok=1", str(r))
            r = await call("run_command", connection="box", command="sleep 5", timeout=1)
            check("run_command timeout", r.get("timed_out") is True and r.get("exit_code") is None, str(r))
            r = await call("run_command", connection="box", command="head -c 300000 /dev/zero | tr '\\0' x")
            check("run_command output cap", len(r.get("stdout", "")) == 100_000
                  and r.get("stdout_truncated_bytes") == 200_000, str({k: v for k, v in r.items() if k != "stdout"}))
            r = await call("run_command", connection="files", command="ls")
            check("run_command refused on ftp", "__error__" in r)

            # Files over SFTP (box-key has default_dir=/site)
            src = local / "proj"
            (src / "sub").mkdir(parents=True)
            (src / "a.txt").write_text("alpha")
            (src / "sub" / "b.txt").write_text("한글 bravo", encoding="utf-8")
            (local / "single.bin").write_bytes(bytes(range(256)) * 4)

            for conn, root in (("box-key", ssh_root / "site"), ("files", ftp_root)):
                tag = f"[{conn}]"
                u = await call("upload", connection=conn, local_path=str(src), remote_path="deploy")
                check(f"{tag} upload dir", u.get("files") == 2 and (root / "deploy" / "sub" / "b.txt").exists(), str(u))
                u = await call("upload", connection=conn, local_path=str(local / "single.bin"), remote_path="deploy")
                check(f"{tag} upload file into dir", (root / "deploy" / "single.bin").stat().st_size == 1024, str(u))
                u = await call("upload", connection=conn, local_path=str(local / "single.bin"),
                               remote_path="deploy/single.bin", overwrite=False)
                check(f"{tag} upload overwrite=False refused", "__error__" in u, str(u))
                ls = await call("list_dir", connection=conn, path="deploy")
                names = [e["name"] for e in ls.get("entries", [])]
                check(f"{tag} list_dir", names == ["sub", "a.txt", "single.bin"], str(ls))
                rf = await call("read_file", connection=conn, path="deploy/sub/b.txt")
                check(f"{tag} read_file utf-8", rf.get("content") == "한글 bravo", str(rf))
                rf = await call("read_file", connection=conn, path="deploy/single.bin")
                check(f"{tag} read_file binary detected", rf.get("binary") is True, str(rf))
                wf = await call("write_file", connection=conn, path="notes/new/log.txt", content="line1\n")
                wf = await call("write_file", connection=conn, path="notes/new/log.txt", content="line2\n", append=True)
                check(f"{tag} write_file + append", (root / "notes/new/log.txt").read_text() == "line1\nline2\n", str(wf))
                mv = await call("move_path", connection=conn, src="notes/new/log.txt", dst="notes/log.txt")
                check(f"{tag} move_path", (root / "notes/log.txt").exists(), str(mv))
                md = await call("make_dir", connection=conn, path="x/y/z")
                check(f"{tag} make_dir -p", (root / "x/y/z").is_dir(), str(md))
                dest = local / f"dl-{conn}"
                d = await call("download", connection=conn, remote_path="deploy", local_path=str(dest))
                check(f"{tag} download dir", d.get("files") == 3 and
                      (dest / "sub" / "b.txt").read_text(encoding="utf-8") == "한글 bravo", str(d))
                de = await call("delete_path", connection=conn, path="x")
                check(f"{tag} delete non-empty dir w/o recursive refused", "__error__" in de, str(de))
                de = await call("delete_path", connection=conn, path="deploy", recursive=True)
                check(f"{tag} delete recursive", not (root / "deploy").exists(), str(de))
                de = await call("delete_path", connection=conn, path="/")
                check(f"{tag} delete root refused", "__error__" in de, str(de))

            bad = await call("run_command", connection="nope", command="ls")
            check("unknown connection error lists names", "__error__" in bad and "box" in bad["__error__"], str(bad))

            # Sessions are pooled: kill server-side connection, next call reconnects.
            await call("disconnect", connection="box")
            r = await call("run_command", connection="box", command="echo again")
            check("reconnect after disconnect", r.get("stdout") == "again\n", str(r))

            # Host key change must be refused.
            ssh.stop()
            ssh = local_servers.start_ssh(ssh_port, ssh_root, {"alice": SSH_PW},
                                          asyncssh.generate_private_key("ssh-ed25519"), [], SSH_PW)
            await call("disconnect", connection="box")
            r = await call("run_command", connection="box", command="echo should-not-run")
            check("changed host key refused", "__error__" in r and "key" in r["__error__"].lower(), str(r))

            rm = await call("remove_connection", name="files")
            check("remove_connection", "removed" in rm and keyring.get_password(SERVICE, "files") is None, str(rm))

        leaked = [sec for sec in SECRETS if any(sec in t for t in transcript)]
        check("no secret ever returned to the agent", not leaked, f"leaked: {leaked}")
        on_disk = (home / "connections.json").read_text()
        check("no secret in connections.json", not any(sec in on_disk for sec in SECRETS))
        check("secrets in OS keyring", SSH_PW in (keyring.get_password(SERVICE, "box") or ""))
    finally:
        for n in ("box", "box-key", "files"):
            try:
                keyring.delete_password(SERVICE, n)
            except keyring.errors.PasswordDeleteError:
                pass
        ssh.stop()
        ftp.close_all()

    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
