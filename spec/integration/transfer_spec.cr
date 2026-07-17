{% skip_file unless flag?(:integration) %}
require "./integration_helper"

# Regression coverage for silent transfer truncation. A single libssh2
# channel_write / channel_read is partial; the IO#write override (channel.cr)
# and scp_recv_file (session.cr) must loop until the whole payload is
# transferred. Payloads here exceed one SSH packet (32 KB) on purpose.
describe "SSH2 large transfers" do
  # Exercises Channel#write via IO.copy (32 KB blocks) — the path direct_tcpip
  # tunnels and scp uploads share.
  it "sends a payload larger than one SSH packet without truncation" do
    payload = "A" * 5_000_000
    Integration.connect do |session|
      fn = "/tmp/ssh2_send_probe.bin"
      session.scp_send(fn, 0o644, payload.bytesize) do |chan|
        IO.copy(IO::Memory.new(payload), chan)
      end
      session.open_session do |chan|
        chan.command("wc -c < #{fn}")
        chan.gets_to_end.strip.should eq(payload.bytesize.to_s)
      end
    end
  end

  # Exercises scp_recv_file: a single partial read must not leave the tail of
  # the file zero-padded.
  it "downloads a file larger than one SSH packet without truncation" do
    size = 5_000_000
    Integration.connect do |session|
      fn = "/tmp/ssh2_recv_probe.bin"
      session.open_session do |chan|
        chan.command("head -c #{size} /dev/zero | tr '\\0' 'A' > #{fn}")
        chan.gets_to_end
      end

      local = ::File.tempname("ssh2_recv", ".bin")
      begin
        session.scp_recv_file(fn, local)
        content = ::File.read(local)
        content.bytesize.should eq(size)
        # no silent zero-padding: every byte must be the 'A' we wrote
        content.count('A').should eq(size)
      ensure
        ::File.delete?(local)
      end
    end
  end
end
