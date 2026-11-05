"""Human-side CLI: add/edit connections and type secrets without an agent seeing them."""

from __future__ import annotations

import argparse
import getpass
import json
import sys

import paramiko

from .sessions import SessionPool, SSHSession
from .store import Profile, Store


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or (default or "")


def cmd_add(args: argparse.Namespace, store: Store) -> int:
    existing = None
    try:
        existing = store.get(args.name)
    except KeyError:
        pass
    if existing and not args.overwrite:
        print(f"'{args.name}' already exists; use `remote-vault edit {args.name}` or --overwrite", file=sys.stderr)
        return 1

    protocol = args.protocol or _ask("protocol (ssh/ftp/ftps)", "ssh")
    host = args.host or _ask("host")
    username = args.user or _ask("username")
    profile = Profile(
        name=args.name, protocol=protocol, host=host, username=username, port=args.port or 0,
        key_path=args.key, default_dir=args.dir, description=args.desc or "",
    )

    password = passphrase = None
    if profile.key_path:
        passphrase = getpass.getpass("key passphrase (blank if none): ")
    if not args.no_password and (args.password or not profile.key_path):
        password = getpass.getpass(f"password for {username}@{host} (blank for key/agent auth): ")

    store.put(profile, overwrite=True)
    store.set_secrets(profile.name, password=password or None, passphrase=passphrase or None)
    print(f"saved '{profile.name}' ({profile.protocol}://{username}@{host}:{profile.port})")
    if args.test:
        return cmd_test(argparse.Namespace(name=profile.name), store)
    return 0


def cmd_edit(args: argparse.Namespace, store: Store) -> int:
    p = store.get(args.name)
    for attr, value in (("host", args.host), ("username", args.user), ("port", args.port),
                        ("key_path", args.key), ("default_dir", args.dir), ("description", args.desc)):
        if value is not None:
            setattr(p, attr, value or None if attr in ("key_path", "default_dir") else value)
    store.put(Profile(**p.__dict__), overwrite=True)
    if args.password:
        store.set_secrets(p.name, password=getpass.getpass("new password (blank to clear): "))
    if args.passphrase:
        store.set_secrets(p.name, passphrase=getpass.getpass("new key passphrase (blank to clear): "))
    print(f"updated '{p.name}'")
    return 0


def cmd_list(args: argparse.Namespace, store: Store) -> int:
    profiles = store.list()
    if args.json:
        print(json.dumps([p.public_view(store) for p in profiles], indent=2, ensure_ascii=False))
        return 0
    if not profiles:
        print("no connections yet. add one with: remote-vault add <name>")
        return 0
    for p in profiles:
        v = p.public_view(store)
        extra = f"  dir={p.default_dir}" if p.default_dir else ""
        print(f"{p.name:<20} {p.protocol:<5} {p.username}@{p.host}:{p.port}  auth={v['auth']}{extra}"
              + (f"  # {p.description}" if p.description else ""))
    return 0


def cmd_remove(args: argparse.Namespace, store: Store) -> int:
    store.remove(args.name)
    print(f"removed '{args.name}'")
    return 0


def cmd_test(args: argparse.Namespace, store: Store) -> int:
    store.get(args.name)  # unknown names are reported by main()
    pool = SessionPool(store)
    try:
        sess = pool.get(args.name)
        if isinstance(sess, SSHSession):
            r = sess.exec("whoami", timeout=15)
            print(f"ok: logged in as {r['stdout'].strip() or '?'}; home = {sess.sftp.normalize('.')}")
        else:
            print(f"ok: {sess.ftp.getwelcome()}; cwd = {sess.ftp.pwd()}")
        return 0
    except paramiko.BadHostKeyException as e:
        print(f"HOST KEY CHANGED for {e.hostname}! refusing to connect. If this is expected, run:\n"
              f"  remote-vault forget-host {e.hostname}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001 - surface any connection error to the user
        print(f"failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    finally:
        pool.close_all()


def cmd_run(args: argparse.Namespace, store: Store) -> int:
    store.get(args.name)
    pool = SessionPool(store)
    try:
        sess = pool.get(args.name)
        if not isinstance(sess, SSHSession):
            print("run needs an ssh connection", file=sys.stderr)
            return 1
        r = sess.exec(" ".join(args.command), timeout=args.timeout, sudo=args.sudo)
        sys.stdout.write(r["stdout"])
        sys.stderr.write(r["stderr"])
        return r["exit_code"] if r["exit_code"] is not None else 124
    finally:
        pool.close_all()


def cmd_forget_host(args: argparse.Namespace, store: Store) -> int:
    path = store.home / "known_hosts"
    keys = paramiko.HostKeys(str(path)) if path.exists() else paramiko.HostKeys()
    targets = [h for h in keys.keys() if h == args.host or h.startswith(f"[{args.host}]:")]
    for h in targets:
        del keys[h]
    keys.save(str(path))
    print(f"removed {len(targets)} entr{'y' if len(targets) == 1 else 'ies'} for {args.host}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="remote-vault", description="Manage connections for the remote-vault MCP server.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def conn_opts(p: argparse.ArgumentParser) -> None:
        p.add_argument("--host")
        p.add_argument("--user")
        p.add_argument("--port", type=int)
        p.add_argument("--key", help="path to a private key file (ssh)")
        p.add_argument("--dir", help="default remote directory")
        p.add_argument("--desc", help="free-text description shown to agents")

    p = sub.add_parser("add", help="add a connection (prompts for secrets)")
    p.add_argument("name")
    p.add_argument("--protocol", choices=["ssh", "sftp", "ftp", "ftps"])
    conn_opts(p)
    p.add_argument("--password", action="store_true", help="also ask for a password when using --key (for sudo)")
    p.add_argument("--no-password", action="store_true", help="don't ask for a password")
    p.add_argument("--overwrite", action="store_true")
    p.add_argument("--test", action="store_true", help="test the connection after saving")
    p.set_defaults(fn=cmd_add)

    p = sub.add_parser("edit", help="change fields of a connection")
    p.add_argument("name")
    conn_opts(p)
    p.add_argument("--password", action="store_true", help="prompt for a new password")
    p.add_argument("--passphrase", action="store_true", help="prompt for a new key passphrase")
    p.set_defaults(fn=cmd_edit)

    p = sub.add_parser("list", help="list connections")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("remove", help="delete a connection and its secrets")
    p.add_argument("name")
    p.set_defaults(fn=cmd_remove)

    p = sub.add_parser("test", help="try to connect")
    p.add_argument("name")
    p.set_defaults(fn=cmd_test)

    p = sub.add_parser("run", help="run a command over ssh")
    p.add_argument("name")
    p.add_argument("command", nargs=argparse.REMAINDER)
    p.add_argument("--timeout", type=float, default=120)
    p.add_argument("--sudo", action="store_true")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("forget-host", help="drop a remembered host key (after a legit key change)")
    p.add_argument("host")
    p.set_defaults(fn=cmd_forget_host)

    args = ap.parse_args(argv)
    try:
        return args.fn(args, Store())
    except (KeyError, ValueError) as e:
        print(f"error: {e.args[0] if e.args else e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
