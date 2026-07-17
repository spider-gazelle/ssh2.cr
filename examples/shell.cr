require "../src/ssh2"

SSH2::Session.open("my_server") do |session|
  session.login("username", "password")
  session.open_session do |chan|
    chan.request_pty("vt100")
    chan.shell

    # forward local STDIN to the remote shell in a background fiber
    spawn do
      while line = gets
        chan.write("#{line}\n".to_slice)
      end
      chan.send_eof
    end

    # stream the remote output until the channel reports EOF
    buf = Bytes.new(1024)
    until chan.eof?
      len = chan.read(buf)
      print String.new(buf[0, len]) if len > 0
    end
  end
end
