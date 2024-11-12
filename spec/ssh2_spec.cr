require "../src/ssh2"
require "spec"

SPEC_SSH_HOST = ENV["SPEC_SSH_HOST"]? || "localhost"
SPEC_SSH_PORT = ENV["CI"]? ? 22 : 10022

def connect_ssh
  SSH2::Session.open(SPEC_SSH_HOST, SPEC_SSH_PORT) do |session|
    session.login("root", "somepassword")
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

  it "should be able to connect in interactive mode" do
    SSH2::Session.open(SPEC_SSH_HOST, SPEC_SSH_PORT) do |session|
      pending!("container doesn't support interactive login...")
      session.interactive_login("root") { "somepassword" }

      session.open_session do |channel|
        channel.command("uptime")
        resp = channel.read_line
        resp.match(/load average/).should_not be_nil
        channel.exit_status.should eq(0)
      end
    end
  end

  it "should obtain a list of supported auth methods" do
    SSH2::Session.open(SPEC_SSH_HOST, SPEC_SSH_PORT) do |session|
      methods = session.login_with_noauth("root")
      methods.should eq(["publickey", "password", "keyboard-interactive"])
    end
  end

  it "should be able to scp transfer file" do
    fn = "#{Time.utc.to_unix}.txt"
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

      # NOTE:: technically the type mask can be generated programatically
      # by shifting the key_type integer value by 18
      # https://github.com/libssh2/libssh2/blob/6c7769dcc422250d14af1b06fce378b6ee009440/include/libssh2.h#L996
      case key_type
      when LibSSH2::HostKeyType::RSA
        typemask |= LibSSH2::TypeMask::KEY_SSHRSA
      when LibSSH2::HostKeyType::DSS
        typemask |= LibSSH2::TypeMask::KEY_SSHDSS
      when LibSSH2::HostKeyType::ECDSA_256
        typemask |= LibSSH2::TypeMask::KEY_ECDSA_256
      when LibSSH2::HostKeyType::ECDSA_384
        typemask |= LibSSH2::TypeMask::KEY_ECDSA_384
      when LibSSH2::HostKeyType::ECDSA_521
        typemask |= LibSSH2::TypeMask::KEY_ECDSA_521
      when LibSSH2::HostKeyType::ED25519
        typemask |= LibSSH2::TypeMask::KEY_ED25519
      else
        fail "unknown key_type: #{key_type}"
      end
      known_hosts.add(SPEC_SSH_HOST, "", key, "comment", typemask)
      known_hosts.add("127.0.0.1", "", key, "comment", typemask)
      known_hosts.size.should eq(2)
      known_hosts.map(&.name).includes?(SPEC_SSH_HOST).should be_true
      known_hosts.write_file("known_hosts")
      known_hosts.delete_if { |h| h.name == SPEC_SSH_HOST }
      known_hosts.size.should eq(1)
    end

    connect_ssh do |session|
      known_hosts = session.knownhosts
      known_hosts.read_file("known_hosts")
      key, _ = session.hostkey
      host = known_hosts.check(SPEC_SSH_HOST, SPEC_SSH_PORT, key, LibSSH2::TypeMask::PLAIN | LibSSH2::TypeMask::KEYENC_RAW)
      host.should eq(LibSSH2::KnownHostCheck::MATCH)
    end
    File.delete("known_hosts")
  end
end

describe SSH2::SFTP do
  it "should be able to list directory" do
    connect_ssh do |ssh|
      ssh.sftp_session do |sftp|
        dir = sftp.open_dir("/usr/bin/")
        files = dir.ls
        files.empty?.should be_false
        files.includes?("scp").should be_true
      end
    end
  end

  it "should be able to retrieve a file" do
    connect_ssh do |ssh|
      ssh.sftp_session do |sftp|
        file = sftp.open("/etc/resolv.conf")
        attrs = file.fstat
        attrs.atime.should be_a(Time)
        attrs.permissions.to_s(8).should eq("100644")
        file.gets_to_end.should match(/nameserver/)
      end
    end
  end

  it "should be able to upload a file" do
    connect_ssh do |ssh|
      ssh.sftp_session do |sftp|
        fn = "#{Time.utc.to_unix}_upload.txt"
        file = sftp.open(fn, "wc", 0o644)
        file.puts "hello world!"
        attrs = file.fstat
        attrs.size.should eq(13)
      end
    end
    GC.collect
  end
end
