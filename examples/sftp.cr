require "../src/ssh2"

SSH2::Session.open("localhost", 2222) do |session|
  session.login_with_pubkey("root", "./spec/keys/id_rsa")
  session.sftp_session do |sftp|
    sftp.open_dir(".").ll do |fn|
      puts fn
    end
    file = sftp.open(".bashrc")
    puts file.read
  end
end
