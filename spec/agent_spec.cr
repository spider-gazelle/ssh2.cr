require "./spec_helper"

# Serverless regression for the `PublicKey` constructor. It used to be named
# `initiation` (a typo), which made `PublicKey.new(...)` — and therefore
# `Agent#each` — fail to compile.
describe SSH2::Agent::PublicKey do
  it "constructs from a key blob and a comment" do
    key = SSH2::Agent::PublicKey.new(Bytes[1_u8, 2_u8, 3_u8], "user@host")
    key.public_key.should eq(Bytes[1_u8, 2_u8, 3_u8])
    key.comment.should eq("user@host")
  end
end
