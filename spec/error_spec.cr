require "./spec_helper"

# Pure, serverless coverage of the SFTP status-code -> exception mapping.
describe SSH2::SFTPError do
  describe ".check_error" do
    it "does nothing on success (0)" do
      SSH2::SFTPError.check_error(0_u64)
    end

    it "raises EOF on 1" do
      expect_raises(SSH2::SFTPError::EOF) { SSH2::SFTPError.check_error(1_u64) }
    end

    it "raises NoSuchFile on 2" do
      expect_raises(SSH2::SFTPError::NoSuchFile) { SSH2::SFTPError.check_error(2_u64) }
    end

    it "raises PermissionDenied on 3" do
      expect_raises(SSH2::SFTPError::PermissionDenied) { SSH2::SFTPError.check_error(3_u64) }
    end

    it "raises FileAlreadyExists on 11" do
      expect_raises(SSH2::SFTPError::FileAlreadyExists) { SSH2::SFTPError.check_error(11_u64) }
    end

    it "raises the generic SFTPError on an unknown code" do
      ex = expect_raises(SSH2::SFTPError) { SSH2::SFTPError.check_error(999_u64) }
      ex.message.to_s.should contain("999")
    end
  end
end
