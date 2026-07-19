{% skip_file unless flag?(:integration) %}
require "./integration_helper"

# Exercises Session#verify_known_host: build a known_hosts file from the live
# container's host key, then confirm the verdicts.
describe "SSH2::Session#verify_known_host" do
  it "returns MATCH for a known host, NOTFOUND for an empty file" do
    known = File.tempname("kh", ".txt")
    begin
      # Build a known_hosts entry for the container using the library's own API.
      Integration.connect do |session|
        kh = session.knownhosts
        key, key_type = session.hostkey
        typemask = LibSSH2::TypeMask::PLAIN
        case key_type
        when LibSSH2::HostKeyType::RSA       then typemask |= LibSSH2::TypeMask::KEY_SSHRSA
        when LibSSH2::HostKeyType::ED25519   then typemask |= LibSSH2::TypeMask::KEY_ED25519
        when LibSSH2::HostKeyType::ECDSA_256 then typemask |= LibSSH2::TypeMask::KEY_ECDSA_256
        else                                      typemask |= LibSSH2::TypeMask::KEY_ED25519
        end
        kh.add(Integration::HOST, "", key, "comment", typemask)
        kh.write_file(known)
      end

      # A fresh session verifies against the file we just wrote.
      Integration.connect do |session|
        session.verify_known_host(Integration::HOST, Integration::PORT, known)
          .should eq(LibSSH2::KnownHostCheck::MATCH)
      end

      # An empty file yields NOTFOUND.
      empty = File.tempname("kh_empty", ".txt")
      File.write(empty, "")
      begin
        Integration.connect do |session|
          session.verify_known_host(Integration::HOST, Integration::PORT, empty)
            .should eq(LibSSH2::KnownHostCheck::NOTFOUND)
        end
      ensure
        File.delete?(empty)
      end
    ensure
      File.delete?(known)
    end
  end
end
