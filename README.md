# remote-vault

**English** | [한국어](#한국어)

An MCP server that lets AI agents (Claude Code, Claude Desktop, etc.) run SSH commands and transfer files over SFTP/FTP **by connection name only — without ever seeing credentials.**

- Host / port / username → `~/.remote-vault/connections.json` (not secret)
- Passwords / key passphrases → **OS keyring** (Windows Credential Manager, macOS Keychain, Linux Secret Service)
- The agent passes only `connection="prod-web"`; passwords are never returned in any response

## Install

Requires Python ≥ 3.10 and [uv](https://docs.astral.sh/uv/).

```bash
git clone <this-repo-url> remote-vault
cd remote-vault
uv tool install --editable .
```

Register with Claude Code:

```bash
claude mcp add -s user remote-vault -- remote-vault-mcp
```

Other MCP clients (e.g. Claude Desktop):

```json
{ "mcpServers": { "remote-vault": { "command": "remote-vault-mcp" } } }
```

## Register connections (do it yourself, so secrets stay out of the chat)

```bash
remote-vault add myserver --protocol ssh --host 192.0.2.10 --user deploy --dir /home/deploy --test
```

```bash
remote-vault add mykey --protocol ssh --host example.com --user deploy --key ~/.ssh/id_ed25519 --password
```

```bash
remote-vault add webhost --protocol ftp --host ftp.example.com --user me
```

| Command | Description |
|---|---|
| `remote-vault add <name>` | Add a connection. Password/passphrase is typed with hidden input |
| `remote-vault edit <name> [--host ..] [--password]` | Edit (`--password` re-prompts for the password) |
| `remote-vault list` | List connections |
| `remote-vault test <name>` | Test the connection |
| `remote-vault run <name> -- uptime` | Run a command directly |
| `remote-vault remove <name>` | Delete (including keyring secrets) |
| `remote-vault forget-host <host>` | Drop a remembered host key after a legitimate key change |

With `--key` alone no password is requested. To use sudo, also store a password via `--password`.
Agents can register connections through the `add_connection` tool, but the password would then appear in the conversation — the CLI is recommended.

## Tools exposed to agents

| Tool | What it does |
|---|---|
| `list_connections` | List registered connections (no secrets) |
| `test_connection` | Check connectivity |
| `run_command` | Run an SSH command → `exit_code`, `stdout`, `stderr`. Supports `cwd`, `timeout`, `stdin`, `sudo` (stored password is fed automatically), `pty` |
| `upload` / `download` | Transfer files and folders (recursive). Creates parent dirs, `overwrite` option |
| `list_dir` | List a remote directory |
| `read_file` / `write_file` | Read / write (append) remote text files |
| `make_dir` / `delete_path` / `move_path` | `mkdir -p`, delete (directories need `recursive=True`; deleting `/` is refused), rename |
| `add_connection` / `remove_connection` | Register / delete connections |
| `disconnect` | Close pooled sessions |

- `ssh` (= `sftp`) profiles support commands + files; `ftp` / `ftps` support files only.
- Relative remote paths resolve against the profile's `default_dir`, which is also the default `cwd` for `run_command`.
- Sessions are reused per connection (keepalive) and reconnect automatically.
- Output is capped at 100 KB per stream; overflow is reported via `stdout_truncated_bytes`.

## Security notes

- **Host keys**: recorded on first connect in `~/.remote-vault/known_hosts` (TOFU); `~/.ssh/known_hosts` is also trusted. A changed key is rejected (MITM protection).
- `sudo=True` sends the password via stdin only, and masks it as `********` if it shows up in output.
- To stop agents from changing the connection list, set `REMOTE_VAULT_LOCK_CONFIG=1` — the `add_connection` / `remove_connection` tools disappear.
- Agents can't see passwords, but they **do** get full command execution on the target. Register production servers with a least-privilege account.

| Environment variable | Default | Purpose |
|---|---|---|
| `REMOTE_VAULT_HOME` | `~/.remote-vault` | Location of profiles / known_hosts |
| `REMOTE_VAULT_KEYRING_SERVICE` | `remote-vault` | Keyring service name |
| `REMOTE_VAULT_LOCK_CONFIG` | (unset) | `1` disables the add/remove tools |

## Development / Testing

```bash
uv sync
uv run python tests/e2e.py
```

The test spins up temporary local SSH/SFTP (asyncssh) and FTP (pyftpdlib) servers, attaches the real MCP server over stdio, and runs 50 checks (password/key auth, sudo, timeouts, output limits, up/downloads, host-key-change rejection, no secrets leaking into responses or disk, etc.).

---

## 한국어

AI 에이전트(Claude Code 등)가 **접속 정보 없이 이름만으로** SSH 명령 실행, SFTP/FTP 파일 전송을 할 수 있게 해주는 MCP 서버입니다.

- 아이디/호스트/포트 → `~/.remote-vault/connections.json` (비밀 아님)
- 비밀번호/키 패스프레이즈 → **OS 키링** (Windows 자격 증명 관리자 / macOS 키체인 / Linux Secret Service)
- 에이전트는 `connection="prod-web"` 처럼 이름만 넘기고, 비밀번호는 어떤 응답에도 돌아가지 않음

### 설치

Python 3.10 이상, [uv](https://docs.astral.sh/uv/) 필요.

```bash
git clone <this-repo-url> remote-vault
cd remote-vault
uv tool install --editable .
```

Claude Code에 등록:

```bash
claude mcp add -s user remote-vault -- remote-vault-mcp
```

Claude Desktop 등 다른 클라이언트는 설정 파일에:

```json
{ "mcpServers": { "remote-vault": { "command": "remote-vault-mcp" } } }
```

### 접속 정보 등록 (사람이 직접 — 비밀번호가 채팅에 안 남음)

```bash
remote-vault add myserver --protocol ssh --host 192.0.2.10 --user deploy --dir /home/deploy --test
```

```bash
remote-vault add mykey --protocol ssh --host example.com --user deploy --key ~/.ssh/id_ed25519 --password
```

```bash
remote-vault add webhost --protocol ftp --host ftp.example.com --user me
```

| 명령 | 설명 |
|---|---|
| `remote-vault add <이름>` | 등록. 비밀번호/패스프레이즈는 화면에 안 보이게 입력받음 |
| `remote-vault edit <이름> [--host ..] [--password]` | 수정 (`--password` 주면 비번 다시 입력) |
| `remote-vault list` | 목록 |
| `remote-vault test <이름>` | 접속 테스트 |
| `remote-vault run <이름> -- uptime` | 바로 명령 실행 |
| `remote-vault remove <이름>` | 삭제 (키링 비밀도 같이) |
| `remote-vault forget-host <호스트>` | 서버 호스트 키가 정상적으로 바뀌었을 때 기억된 키 삭제 |

`--key`만 주면 비밀번호는 안 물어봅니다. sudo를 쓸 거면 `--password`로 비번도 저장하세요.
에이전트가 `add_connection` 툴로 직접 등록할 수도 있지만, 이 경우 비번이 대화에 남으니 CLI를 권장합니다.

### 에이전트가 쓰는 툴

| 툴 | 하는 일 |
|---|---|
| `list_connections` | 등록된 접속 목록 (비밀 제외) |
| `test_connection` | 접속 확인 |
| `run_command` | SSH 명령 실행 → `exit_code`, `stdout`, `stderr`. `cwd`, `timeout`, `stdin`, `sudo`(저장된 비번 자동 입력), `pty` 지원 |
| `upload` / `download` | 파일·폴더(재귀) 전송. 상위 폴더 자동 생성, `overwrite` 옵션 |
| `list_dir` | 원격 폴더 목록 |
| `read_file` / `write_file` | 원격 텍스트 파일 읽기/쓰기(append) |
| `make_dir` / `delete_path` / `move_path` | mkdir -p, 삭제(폴더는 `recursive=True` 필요, `/` 삭제 거부), 이름 변경 |
| `add_connection` / `remove_connection` | 접속 등록/삭제 |
| `disconnect` | 풀링된 세션 끊기 |

- `ssh`(=`sftp`) 프로필은 명령 + 파일, `ftp`/`ftps`는 파일만 지원합니다.
- 원격 상대경로는 프로필의 `default_dir` 기준이며, `run_command`의 기본 `cwd`도 `default_dir`입니다.
- 접속은 이름별로 재사용(keepalive)되고, 끊기면 다음 호출 때 자동 재연결됩니다.
- 출력은 스트림당 100KB까지이며, 넘으면 `stdout_truncated_bytes`로 알려줍니다.

### 보안 메모

- **호스트 키**: 처음 접속 시 `~/.remote-vault/known_hosts`에 기록(TOFU) + `~/.ssh/known_hosts`도 신뢰. 이후 키가 바뀌면 접속 거부 (MITM 방지).
- `sudo=True`는 비번을 stdin으로만 넘기고, 출력에 비번이 섞이면 `********`로 가림.
- 에이전트가 접속 목록을 바꾸지 못하게 하려면 서버 환경변수 `REMOTE_VAULT_LOCK_CONFIG=1` → `add_connection`/`remove_connection` 툴이 사라짐.
- 에이전트는 비번을 못 보지만, **명령 실행 권한 자체는 그대로** 가집니다. 운영 서버는 권한이 제한된 계정으로 등록하는 걸 추천합니다.

| 환경변수 | 기본값 | 용도 |
|---|---|---|
| `REMOTE_VAULT_HOME` | `~/.remote-vault` | 프로필/known_hosts 위치 |
| `REMOTE_VAULT_KEYRING_SERVICE` | `remote-vault` | 키링 서비스 이름 |
| `REMOTE_VAULT_LOCK_CONFIG` | (없음) | `1`이면 등록/삭제 툴 비활성화 |

### 개발 / 테스트

```bash
uv sync
uv run python tests/e2e.py
```

로컬에 임시 SSH/SFTP 서버(asyncssh)와 FTP 서버(pyftpdlib)를 띄우고, 실제 MCP 서버를 stdio로 붙여서 50개 항목을 검사합니다
(비번/키 인증, sudo, 타임아웃, 출력 제한, 업·다운로드, 호스트 키 변경 거부, 비밀이 응답·디스크에 안 새는지 등).
