require "./src/ssh2"

SSH2::Session.open("localhost", 2222) do |session|
  session.open_session do |ch|
    # THE FOLLOWING LINE CRASHES COMPILER
    loop {}
  end
end
