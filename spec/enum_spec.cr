require "./spec_helper"

# Serverless: guards the numeric values of the protocol enums against
# accidental reordering (they must match the libssh2 / RFC 4254 constants).
describe SSH2::TerminalMode do
  it "matches the RFC 4254 terminal-mode opcodes" do
    SSH2::TerminalMode::VINTR.value.should eq(1)
    SSH2::TerminalMode::ECHO.value.should eq(53)
    SSH2::TerminalMode::TTY_OP_OSPEED.value.should eq(129)
  end
end

describe LibSSH2::HostKeyType do
  it "matches the libssh2 host-key type constants" do
    LibSSH2::HostKeyType::UNKNOWN.value.should eq(0)
    LibSSH2::HostKeyType::RSA.value.should eq(1)
    LibSSH2::HostKeyType::ED25519.value.should eq(6)
  end
end
