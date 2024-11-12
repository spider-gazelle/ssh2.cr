require "../src/ssh2"

SSH2::Session.open("my_server") do |session|
  session.login("username", "password")
  session.open_session do |chan|
    chan.request_pty("vt100")
    chan.shell
    session.blocking = false

    buf_space = Bytes.new(1024)
    buf = buf_space.to_slice
    loop do
      io = IO.select([STDIN, chan.socket]).first
      if io == STDIN
        command = gets
        if command
          chan.write(command.to_slice)
        end
      elsif io == chan.socket
        len = chan.read(buf).to_i32
        print! String.new buf[0, len]
        break if chan.eof?
      end
    end
  end
end
