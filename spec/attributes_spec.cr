require "./spec_helper"

# Pure, serverless coverage of the SFTPAttrs wrapper: getters/setters and the
# UInt64 <-> Time / Flags conversions. No SSH connection involved.
describe SSH2::SFTP::Attributes do
  it "defaults to an all-zero attribute set" do
    attrs = SSH2::SFTP::Attributes.new
    attrs.flags.should eq(SSH2::SFTP::Attributes::Flags::None)
    attrs.size.should eq(0)
    attrs.uid.should eq(0)
    attrs.gid.should eq(0)
    attrs.permissions.should eq(0)
  end

  it "wraps an existing libssh2 struct" do
    stat = LibSSH2::SFTPAttrs.new
    stat.filesize = 42_u64
    attrs = SSH2::SFTP::Attributes.new(stat)
    attrs.size.should eq(42)
  end

  it "round-trips the flags bitmask" do
    attrs = SSH2::SFTP::Attributes.new
    attrs.flags = SSH2::SFTP::Attributes::Flags::SIZE | SSH2::SFTP::Attributes::Flags::PERMISSIONS
    attrs.flags.size?.should be_true
    attrs.flags.permissions?.should be_true
    attrs.flags.uidgid?.should be_false
  end

  it "round-trips uid and gid" do
    attrs = SSH2::SFTP::Attributes.new
    attrs.uid = 1000
    attrs.gid = 1001
    attrs.uid.should eq(1000)
    attrs.gid.should eq(1001)
  end

  it "round-trips permissions" do
    attrs = SSH2::SFTP::Attributes.new
    attrs.permissions(0o644)
    attrs.permissions.should eq(0o644)
  end

  it "exposes atime and mtime as UTC Time truncated to the second" do
    attrs = SSH2::SFTP::Attributes.new
    attrs.atime = Time.unix(1_600_000_000)
    attrs.mtime = Time.unix(1_600_000_500)
    attrs.atime.should eq(Time.unix(1_600_000_000))
    attrs.mtime.should eq(Time.unix(1_600_000_500))
  end
end
