require "../src/ssh2"
require "spec"

def connect_ssh
  SSH2::Session.open("localhost", 2222) do |session|
    session.login_with_pubkey("root", "./spec/keys/id_rsa")
    session.authenticated?.should be_true
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
        channel.exit_status.should eq(0)
      end
    end
  end

  it "should be able to scp transfer file" do
    fn = "#{Time.now.epoch}.txt"
    connect_ssh do |session|
      session.scp_send(fn, 0o0644, 12) do |ch|
        ch.puts "hello world"
      end
      session.open_session do |ch|
        ch.command("ls -l")
        ch.gets_to_end.includes?(fn).should be_true
      end
      session.scp_recv(fn) do |ch, st|
        buf = Slice(UInt8).new(st.st_size.to_i32)
        ch.read(buf)
        String.new(buf).should eq("hello world\n")
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
      known_hosts.size.should eq(2)
      known_hosts.map(&.name).includes?("localhost").should be_true
      known_hosts.write_file("known_hosts")
      known_hosts.delete_if {|h| h.name == "localhost"}
      known_hosts.size.should eq(1)
    end

    connect_ssh do |session|
      known_hosts = session.knownhosts
      known_hosts.read_file("known_hosts")
      key, key_type = session.hostkey
      host = known_hosts.check("localhost", 2222, key, LibSSH2::TypeMask::PLAIN | LibSSH2::TypeMask::KEYENC_RAW)
      host.should eq(LibSSH2::KnownHostCheck::MATCH)
    end
    File.delete("known_hosts")
  end
end

describe SSH2::SFTP do
  it "should be able to list directory" do
    connect_ssh do |ssh|
      ssh.sftp_session do |sftp|
        dir = sftp.open_dir(".")
        files = dir.ls
        files.empty?.should be_false
        files.includes?(".bashrc").should be_true
      end
    end
  end

  it "should be able to retrieve a file" do
    connect_ssh do |ssh|
      ssh.sftp_session do |sftp|
        file = sftp.open(".bashrc")
        attrs = file.fstat
        attrs.atime.should be_a(Time)
        attrs.permissions.to_s(8).should eq("100644")
        file.gets_to_end.should match(/.bashrc/)
      end
    end
  end

  it "should be able to upload a file" do
    connect_ssh do |ssh|
      ssh.sftp_session do |sftp|
        fn = "#{Time.now.epoch}_upload.txt"
        file = sftp.open(fn, "wc", 0o644)
        file.puts "hello world!"
        attrs = file.fstat
        attrs.size.should eq(13)
      end
    end
  end
end
