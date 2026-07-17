{% skip_file unless flag?(:integration) %}
require "./integration_helper"

describe SSH2::KnownHosts do
  it "should be able to write and check known_hosts" do
    Integration.connect do |session|
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
      known_hosts.add(Integration::HOST, "", key, "comment", typemask)
      known_hosts.add("127.0.0.1", "", key, "comment", typemask)
      known_hosts.size.should eq(2)
      known_hosts.map(&.name).includes?(Integration::HOST).should be_true
      known_hosts.write_file("known_hosts")
      known_hosts.delete_if { |host| host.name == Integration::HOST }
      known_hosts.size.should eq(1)
    end

    Integration.connect do |session|
      known_hosts = session.knownhosts
      known_hosts.read_file("known_hosts")
      key, _ = session.hostkey
      host = known_hosts.check(Integration::HOST, Integration::PORT, key, LibSSH2::TypeMask::PLAIN | LibSSH2::TypeMask::KEYENC_RAW)
      host.should eq(LibSSH2::KnownHostCheck::MATCH)
    end
    File.delete("known_hosts")
  end
end
