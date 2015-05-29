require "../src/ssh2"
require "spec"

def connect_ssh
  SSH2::Session.open("localhost", 2222) do |session|
    session.login_with_pubkey("root", "./spec/keys/id_rsa")
    yield session
  end
end

describe SSH2 do
  it "should be able to exec commands" do
    connect_ssh do |session|
      session.open_session do |channel|
        channel.command("uptime")
        resp = channel.read_line
        resp.match(/load average/).should_not be_nil
      end
    end
  end

  it "should be able to scp transfer file" do
    fn = "#{Time.now.to_i}.txt"
    connect_ssh do |session|
      session.scp_send(fn, 0644, 12) do |ch|
        ch.puts "hello world"
      end
      session.open_session do |ch|
        ch.command("ls -l")
        ch.read.includes?(fn).should be_true
      end
      session.scp_recv(fn) do |ch, st|
        ch.read(st.st_size.to_i32).should eq("hello world\n")
      end
    end
  end
end
