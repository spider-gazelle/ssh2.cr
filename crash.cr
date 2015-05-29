require "./src/ssh2"

SSH2::Session.open("localhost", 2222) do |session|
  session.login_with_pubkey("root", "./spec/keys/id_rsa")
  session.open_session do |ch|
    ch.request_pty("vanilla")
    ch.shell
    session.blocking = false

    # THE FOLLOWING LINE CRASHES COMPILER
    loop {}
  end
end
