require "../src/ssh2"

SSH2::Session.open("my_server") do |session|
  session.login("username", "password")
  session.open_session do |ch|
    ch.request_pty("vt100")
    ch.shell
    session.blocking = false

    buf_space = Bytes.new(1024)
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
        print! String.new buf[0, len]
        break if ch.eof?
      end
    end
  end
end
