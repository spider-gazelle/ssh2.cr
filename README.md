# ssh2.cr

[![Build Status](https://travis-ci.org/spider-gazelle/ssh2.cr?branch=master)](https://travis-ci.org/spider-gazelle/ssh2.cr)

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
require "./src/ssh2"

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
require "./src/ssh2"

SSH2::Session.open("localhost", 2222) do |session|
  session.login_with_pubkey("root", "./spec/keys/id_rsa")
  session.open_session do |ch|
    ch.request_pty("vt100")
    ch.shell
    session.blocking = false

    buf_space = uninitialized UInt8[1024]
    buf = buf_space.to_slice
    loop do
      io = IO.select([STDIN, ch.socket]).first
      if io == STDIN
        command = gets
        if command
          ch.write(command.to_slice)
        end
      elsif io == ch.socket
        len = ch.read(buf).to_i32
        print String.new buf[0, len]
        break if ch.eof?
      end
    end
  end
end
```

An example of using SFTP API:

```crystal
require "./src/ssh2"

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
