require "./spec_helper"

# Serverless: the version string comes straight from the linked libssh2, no
# connection required.
describe SSH2 do
  describe ".version" do
    it "returns the linked libssh2 version" do
      version = SSH2.version
      version.should_not be_empty
      version.should match(/\A\d+\.\d+\.\d+/)
    end
  end
end
