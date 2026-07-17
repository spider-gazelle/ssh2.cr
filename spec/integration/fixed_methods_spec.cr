{% skip_file unless flag?(:integration) %}
require "./integration_helper"

# Coverage for public methods that previously did not compile (and so were
# never exercised): hashkey, method_pref, supported_algs, and the SFTP
# symlink/readlink/realpath family. Running them here both verifies the fixes
# and locks them against regression.
describe "SSH2::Session negotiated-method accessors" do
  it "returns the host key fingerprint" do
    Integration.connect do |session|
      fp = session.hashkey(LibSSH2::HashType::SHA256)
      # colon-separated, zero-padded hex byte pairs
      fp.should match(/\A[0-9a-f]{2}(:[0-9a-f]{2})+\z/)
    end
  end

  it "reports the negotiated method for a transport parameter" do
    Integration.connect do |session|
      session.method_pref(LibSSH2::MethodType::KEX).should_not be_nil
    end
  end

  it "lists supported algorithms for a method type" do
    Integration.connect do |session|
      algs = session.supported_algs(LibSSH2::MethodType::CRYPT_CS)
      algs.should_not be_empty
    end
  end
end

describe "SSH2::SFTP symlink / readlink / realpath" do
  it "creates a symlink and resolves it" do
    Integration.connect do |ssh|
      ssh.sftp_session do |sftp|
        target = "/tmp/ssh2_link_target_#{Time.utc.to_unix_ns}.txt"
        link = "/tmp/ssh2_link_#{Time.utc.to_unix_ns}.lnk"
        file = sftp.open(target, "wc", 0o644)
        file.puts("hello")
        file.close
        begin
          sftp.symlink(target, link)
        rescue SSH2::SSH2Error
          # OpenSSH's sftp-server replies SSH_FX_FAILURE to SYMLINK even when the
          # link is created successfully; the assertions below confirm the result.
        end
        # readlink returns the exact link value we set
        sftp.readlink(link).should eq(target)
        # realpath resolves to an absolute canonical path
        sftp.realpath(link).should_not be_empty
      end
    end
  end
end

describe "SSH2::SFTP mkdir / rmdir / unlink" do
  it "creates and removes a directory" do
    Integration.connect do |ssh|
      dir = "/tmp/ssh2_dir_#{Time.utc.to_unix_ns}"
      ssh.sftp_session do |sftp|
        sftp.mkdir(dir, 0o755)
        sftp.rmdir(dir)
      end
      ssh.open_session do |chan|
        chan.command("test -d #{dir} && echo present || echo absent")
        chan.gets_to_end.strip.should eq("absent")
      end
    end
  end

  it "deletes a file with unlink" do
    Integration.connect do |ssh|
      fn = "/tmp/ssh2_unlink_#{Time.utc.to_unix_ns}.txt"
      ssh.sftp_session do |sftp|
        file = sftp.open(fn, "wc", 0o644)
        file.puts("x")
        file.close
        sftp.unlink(fn)
      end
      ssh.open_session do |chan|
        chan.command("test -f #{fn} && echo present || echo absent")
        chan.gets_to_end.strip.should eq("absent")
      end
    end
  end
end

describe "SSH2::Session#keepalive_config" do
  it "configures keepalive without error" do
    Integration.connect do |session|
      session.keepalive_config(30)
    end
  end
end

describe "SSH2::Agent" do
  it "iterates the identities loaded in the ssh-agent" do
    pending!("requires an ssh-agent (SSH_AUTH_SOCK) with a loaded key on the runner")
    # Never executed here, but compiled: this exercises Agent#each, which builds
    # a PublicKey and would not compile if the constructor regressed.
    Integration.connect do |session|
      agent = SSH2::Agent.new(session)
      agent.connect
      agent.list_identities
      agent.each(&.comment.should(be_a(String)))
      agent.disconnect
    end
  end
end
