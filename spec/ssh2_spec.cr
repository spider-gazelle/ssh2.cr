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

describe SSH2::KnownHosts do
  it "should be able to write and check known_hosts" do
    connect_ssh do |session|
      known_hosts = session.knownhosts
      key, key_type = session.hostkey
      typemask = LibSSH2::TypeMask::PLAIN
      case key_type
      when LibSSH2::HostKeyType::RSA
        typemask |= LibSSH2::TypeMask::KEY_SSHRSA
      when LibSSH2::HostKeyType::DSS
        typemask |= LibSSH2::TypeMask::KEY_SSHDSS
      else
        fail "unknown key_type"
      end
      known_hosts.add("localhost", "", key, "comment", typemask)
      known_hosts.add("127.0.0.1", "", key, "comment", typemask)
      known_hosts.count.should eq(2)
      known_hosts.map(&.name).includes?("localhost").should be_true
      known_hosts.write_file("known_hosts")
      known_hosts.delete_if {|h| h.name == "localhost"}
      known_hosts.count.should eq(1)
    end

    connect_ssh do |session|
      known_hosts = session.knownhosts
      known_hosts.read_file("known_hosts")
      key, key_type = session.hostkey
      host = known_hosts.check("localhost", 2222, key, LibSSH2::TypeMask::PLAIN | LibSSH2::TypeMask::KEYENC_RAW)
      host.should eq(LibSSH2::KnownHostCheck::MATCH)
    end
  end
end
