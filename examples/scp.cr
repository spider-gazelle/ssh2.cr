require "../src/ssh2"

SSH2::Session.open("localhost", 2222) do |session|
  session.login("root", "somepassword")
  # upload a local file, then download it back
  session.scp_send_file("./hello.txt", "/tmp/hello.txt")
  session.scp_recv_file("/tmp/hello.txt", "./hello-copy.txt")
end
