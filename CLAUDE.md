# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Crystal binding for the C library `libssh2`. Provides SSH sessions, remote command
execution, an interactive shell, SCP, SFTP, ssh-agent auth and known_hosts checking.
The shard requires `libssh2 >= 1.11.0` (see `shard.yml`; the README's "1.5.0" is stale).

## Commands

Tooling is driven by [mise](https://mise.jdx.dev) — `mise.toml` pins the Crystal
version and defines every `dev:*` task. CI runs the exact same tasks.

```sh
mise dev:deps           # shards install (fetches ameba, builds bin/ameba)
mise dev:spec           # serverless unit suite — no SSH server needed
mise dev:spec-mt        # same, multi-threaded (-Dpreview_mt fiber-safety gate)
mise dev:ameba          # lint (CI gate)
mise dev:format-check   # formatting gate (mise dev:format to auto-format)
mise dev:docs           # build API docs (fails on doc-comment / compile errors)
mise dev:check          # format-check + ameba + spec + spec-mt in one shot
```

Run a single spec by line: `crystal spec spec/attributes_spec.cr:12`.

### Two test tiers: unit (serverless) and integration (e2e)

- **Unit specs** live at the top of `spec/` (`attributes_spec.cr`, `error_spec.cr`,
  `enum_spec.cr`, `version_spec.cr`). They exercise pure logic (the SFTPAttrs
  wrapper, the SFTP error-code → exception mapping, enum values, `SSH2.version`) and
  need no server. `mise dev:spec` runs only these.
- **Integration specs** live under `spec/integration/` and each begins with
  `{% skip_file unless flag?(:integration) %}`, so they compile only under
  `-Dintegration`. They open a real TCP connection and log in — no mocking.

Run the e2e suite against the bundled `testcontainers/sshd` (host port 10022):

```sh
mise dev:ssh-up             # docker compose up -d --wait
mise dev:spec-integration   # crystal spec --error-trace -Dintegration
mise dev:ssh-down           # docker compose down -v
```

Connection config comes from `spec/integration/integration_helper.cr` via env vars,
all with defaults matching `docker-compose.yml`: `SPEC_SSH_HOST` (`localhost`),
`SPEC_SSH_PORT` (`10022`), `SPEC_SSH_USER` (`root`), `SPEC_SSH_PASS` (`somepassword`).
The port is **not** keyed off `ENV["CI"]` — CI passes the same 10022 via docker compose.

### CI note: libssh2 is a link-time dependency

`src/lib_ssh2.cr` declares `@[Link("ssh2", pkg_config: "libssh2")]`, so every job that
compiles the specs must install libssh2 first (`apt-get install libssh2-1-dev` on Linux,
`brew install libssh2` on macOS) — see `.github/workflows/ci.yml`. The unit jobs run on
the full OS matrix (linux amd64/arm64, macOS arm64/intel); the e2e job is Linux-only
because GitHub-hosted macOS runners have no Docker to run the sshd container.

## Architecture

Layered, bottom to top:

- **`src/lib_ssh2.cr`** — raw `lib LibSSH2` FFI declarations (`fun`, structs, enums like
  `BlockDirections`, `HostKeyType`, error constants). No logic. Edit this only to expose a
  new C symbol.
- **`src/ssh2.cr`** — module entry point. Calls `LibSSH2.init` at load time, defines the
  `TerminalMode` enum, the exception hierarchy (`SSH2Error` → `SessionError`,
  `SFTPError` and its ~20 typed subclasses), and `require`s every other file. `require "ssh2"`
  pulls in the whole shard.
- **`src/session.cr`** — `SSH2::Session`, the hub every other object holds a reference to.
  Owns the `TCPSocket`, the libssh2 handle, and the non-blocking machinery below.
- **`src/channel.cr`** — `SSH2::Channel < IO`. Because it *is* an `IO`, you drive remote
  commands with `IO.copy`, `read_line`, `puts`, etc. `Channel::StreamIO` exposes a single
  stream (e.g. stderr) as its own `IO`.
- **`src/sftp/*.cr`, `src/agent.cr`, `src/known_hosts.cr`, `src/listener.cr`** — feature
  objects, each created from a `Session` and each holding a libssh2 handle.

### The one pattern that governs everything: non-blocking + EAGAIN

The socket is put into non-blocking mode in `Session#initialize` (`self.blocking = false`).
Consequently **every** libssh2 call can return `LIBSSH2_ERROR_EAGAIN` instead of blocking.
Never call a `LibSSH2.*` function that can do I/O directly — wrap it:

- `Session#perform_nonblock { ... }` — for calls returning an `Int` return code.
- `Session#nonblock_handle { ... }` — for calls returning a pointer/handle (checks
  `session_last_errno` for EAGAIN when the handle is null).

Both loop: run the block under `@request_lock` (a `Mutex`, so one session is fiber-safe),
and on `EAGAIN` call `waitsocket` to park the current fiber on the socket until it's
readable/writable, then retry. `waitsocket` asks libssh2 which direction to wait on via
`block_directions`. This is what makes blocking-looking calls cooperate with Crystal's
fiber scheduler — a slow SSH op yields instead of stalling the thread.

Edge case already handled: libssh2 can return EAGAIN with block-directions == 0
(`send_existing` in transport.c). `resolved_directions` treats that as `Outbound` so the
fiber doesn't spin until `read_timeout`. Preserve this if you touch `waitsocket`.

### Passing objects to C: `to_unsafe`

`Session`, `Channel`, `Agent`, etc. each define `to_unsafe` returning their `@handle`, so a
Crystal object can be passed straight into a `LibSSH2.*` call. New wrapper types follow the
same convention (define `to_unsafe`, wrap I/O calls, add a private `check_error`).

### Crystal version constraints

- Building on Crystal 1.15.0 / 1.15.1 is hard-blocked with a `{% raise %}` in `session.cr`.
- `waitsocket` has two implementations selected at compile time: `@socket.wait_readable`
  for Crystal ≤ 1.14.1, and `Crystal::EventLoop.current.wait_readable(@socket)` for ≥ 1.16.
  Any change to socket-waiting must update both macro branches.

## Examples

`examples/exec.cr`, `examples/shell.cr`, `examples/sftp.cr` are runnable references for the
three main use cases; they mirror the README snippets.
