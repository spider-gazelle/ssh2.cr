# ssh2.cr

[![CI](https://github.com/spider-gazelle/ssh2.cr/actions/workflows/ci.yml/badge.svg)](https://github.com/spider-gazelle/ssh2.cr/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/spider-gazelle/ssh2.cr)](https://github.com/spider-gazelle/ssh2.cr/releases)
[![License](https://img.shields.io/github/license/spider-gazelle/ssh2.cr)](LICENSE)

This library provides binding for libssh2 library.


# Requirements

- libssh2 version 1.11.0 or higher

You can use `homebrew` to install the latest libssh2:

```
$ brew install libssh2
```

# Installation

Add the shard to your `shard.yml`:

```yaml
dependencies:
  ssh2:
    github: spider-gazelle/ssh2.cr
```

Then run:

```
shards install
```

# Goal

The goal is to utilize libssh2 API by providing services like ability to run
shell commands via ssh as well as scp and sftp services.

# Usage

An example of running a shell command via SSH on the remote server:

```crystal
require "ssh2"

SSH2::Session.open("my_server") do |session|
  session.login("username", "password")
  session.open_session do |channel|
    channel.command("uptime")
    IO.copy(channel, STDOUT)
  end
end
```

An example of running shell:

```crystal
require "ssh2"

session = SSH2::Session.connect("localhost", 2222)
session.login("root", "somepassword")
channel = session.open_session

# request the terminal has echo mode off
channel.request_pty("vt100", [{SSH2::TerminalMode::ECHO, 0u32}])
channel.shell

# Send commands
spawn {
  list = ["ls\n", "ps aux\n", "uptime\n"]
  loop do
    channel.write(list.sample(1)[0].to_slice)
    sleep 3
  end
}

# Receive responses
raw_data = Bytes.new(2048)
loop do
  bytes_read = channel.read(raw_data)
  puts String.new(raw_data[0, bytes_read])
end
```

An example of transferring files over SCP:

```crystal
require "ssh2"

SSH2::Session.open("localhost", 2222) do |session|
  session.login("root", "somepassword")
  # upload a local file, then download it back
  session.scp_send_file("./hello.txt", "/tmp/hello.txt")
  session.scp_recv_file("/tmp/hello.txt", "./hello-copy.txt")
end
```

An example of using SFTP API:

```crystal
require "ssh2"

SSH2::Session.open("localhost", 2222) do |session|
  # NOTE:: ED25519 based keys only work on latest versions of libssh2
  session.login_with_pubkey("root", "./spec/keys/id_rsa", "./spec/keys/id_rsa.pub")
  session.sftp_session do |sftp|
    sftp.open_dir(".").ll do |fn|
      puts fn
    end
    file = sftp.open(".bashrc")
    puts file.gets_to_end
  end
end
```

# Development

This project uses [mise](https://mise.jdx.dev) to manage the Crystal toolchain and
the developer tasks (`mise tasks` lists them all). Install the dependencies with:

```
mise dev:deps
```

# Testing

The suite is split in two tiers:

- **Unit specs** are serverless and run everywhere:

  ```
  mise dev:spec       # single-threaded
  mise dev:spec-mt    # multi-threaded (fiber-safety gate)
  ```

- **Integration specs** drive a real SSH server (a `testcontainers/sshd` container
  defined in `docker-compose.yml`) and are gated behind `-Dintegration`:

  ```
  mise dev:ssh-up             # start the container
  mise dev:spec-integration   # run the e2e suite
  mise dev:ssh-down           # stop it
  ```

Connection settings default to the container (`localhost:10022`, `root` /
`somepassword`) and can be overridden via the `SPEC_SSH_HOST`, `SPEC_SSH_PORT`,
`SPEC_SSH_USER` and `SPEC_SSH_PASS` environment variables.

# License

MIT clause - see LICENSE for more details.
Many thanks to the original author [Kent Sibilev](https://github.com/datanoise/ssh2.cr)
