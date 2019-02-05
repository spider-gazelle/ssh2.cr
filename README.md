# ssh2.cr

[![Build Status](https://travis-ci.org/spider-gazelle/ssh2.cr.svg?branch=master)](https://travis-ci.org/spider-gazelle/ssh2.cr)

This library provides binding for libssh2 library.


# Requirements

- Crystal language version 0.7.0 and higher.
- libssh2 version 1.5.0 or higher

You can use `homebrew` to install the latest libssh2:

```
$ brew install libssh2
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

session = SSH2::Session.open("localhost", 2222)
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

An example of using SFTP API:

```crystal
require "ssh2"

SSH2::Session.open("localhost", 2222) do |session|
  session.login_with_pubkey("root", "./spec/keys/id_rsa")
  session.sftp_session do |sftp|
    sftp.open_dir(".").ll do |fn|
      puts fn
    end
    file = sftp.open(".bashrc")
    puts file.gets_to_end
  end
end
```

# Testing

In order to run test suite you need to pull and run the following docker container:

```
$ docker pull tutum/ubuntu:trusty
$ docker run -d -p 2222:22 -e AUTHORIZED_KEYS="`cat ./spec/keys/id_rsa.pub`" tutum/ubuntu:trusty
```

# License

MIT clause - see LICENSE for more details.
Many thanks to the original author [Kent Sibilev](https://github.com/datanoise/ssh2.cr)
