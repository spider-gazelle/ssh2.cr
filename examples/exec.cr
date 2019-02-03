require "../src/ssh2"

SSH2::Session.open("my_server") do |session|
  session.login("username", "password")
  session.open_session do |channel|
    channel.command("uptime")
    IO.copy(channel, STDOUT)
  end
end
