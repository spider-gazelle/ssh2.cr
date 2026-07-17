{% skip_file unless flag?(:integration) %}
require "./integration_helper"

describe SSH2::SFTP do
  it "should be able to list directory" do
    Integration.connect do |ssh|
      ssh.sftp_session do |sftp|
        dir = sftp.open_dir("/usr/bin/")
        files = dir.ls
        files.empty?.should be_false
        files.includes?("scp").should be_true
      end
    end
  end

  it "should be able to retrieve a file" do
    Integration.connect do |ssh|
      ssh.sftp_session do |sftp|
        file = sftp.open("/etc/resolv.conf")
        attrs = file.fstat
        attrs.atime.should be_a(Time)
        attrs.permissions.to_s(8).should eq("100644")
        file.gets_to_end.should match(/nameserver/)
      end
    end
  end

  it "should be able to upload a file" do
    Integration.connect do |ssh|
      ssh.sftp_session do |sftp|
        fn = "#{Time.utc.to_unix}_upload.txt"
        file = sftp.open(fn, "wc", 0o644)
        file.puts "hello world!"
        attrs = file.fstat
        attrs.size.should eq(13)
      end
    end
    GC.collect
  end
end
