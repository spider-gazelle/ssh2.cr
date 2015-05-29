require "./src/ssh2"

def process_loop(ch)
  buf_space :: UInt8[1024]
  buf = buf_space.to_slice
  socket = ch.session.socket.not_nil!
  loop do
    case IO.select([STDIN, socket]).first
    when STDIN
      command = gets
      ch.write("#{command}\r\n".to_slice)
    when socket
      len = ch.read(buf).to_i32
      print String.new buf[0, len]
    end
  end
end

SSH2::Session.open("localhost", 2222) do |session|
  session.login_with_pubkey("root", "./spec/keys/id_rsa")
  session.open_session do |ch|
    ch.request_pty("vanilla")
    ch.shell
    session.blocking = false

    # process_loop(ch)

    # THE FOLLOWING LINE CRASHES COMPILER
    loop {}
  end
end
