{% skip_file unless flag?(:integration) %}
require "./integration_helper"

describe SSH2 do
  it "should be able to exec commands" do
    Integration.connect do |session|
      session.open_session do |channel|
        channel.command("uptime")
        resp = channel.read_line
        resp.match(/load average/).should_not be_nil
        channel.exit_status.should eq(0)
      end
    end
  end

  it "should be able to connect in interactive mode" do
    SSH2::Session.open(Integration::HOST, Integration::PORT) do |session|
      pending!("container doesn't support interactive login...")
      session.interactive_login(Integration::USER) { Integration::PASS }

      session.open_session do |channel|
        channel.command("uptime")
        resp = channel.read_line
        resp.match(/load average/).should_not be_nil
        channel.exit_status.should eq(0)
      end
    end
  end

  it "should obtain a list of supported auth methods" do
    SSH2::Session.open(Integration::HOST, Integration::PORT) do |session|
      methods = session.login_with_noauth(Integration::USER)
      methods.should eq(["publickey", "password", "keyboard-interactive"])
    end
  end

  it "should be able to scp transfer file" do
    fn = "#{Time.utc.to_unix}.txt"
    Integration.connect do |session|
      session.scp_send(fn, 0o0644, 12) do |chan|
        chan.puts "hello world"
      end
      session.open_session do |chan|
        chan.command("ls -l")
        chan.gets_to_end.includes?(fn).should be_true
      end
      session.scp_recv(fn) do |chan, stat|
        buf = Slice(UInt8).new(stat.st_size.to_i32)
        chan.read(buf)
        String.new(buf).should eq("hello world\n")
      end
    end
  end
end
