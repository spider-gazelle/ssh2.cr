require "./node"

module SSH2::SFTP
  class File < IO
    include Node

    # This function causes the remote server to synchronize the file data and
    # metadata to disk (like fsync(2)).
    def fsync
      ret = LibSSH2.sftp_fsync(self)
      check_error(ret)
    end

    def seek(offset)
      ret = LibSSH2.sftp_seek(self, offset.to_u64)
      check_error(ret)
    end

    def rewind
      seek(0)
    end

    def tell
      LibSSH2.sftp_tell(self)
    end

    def read(slice : Slice(UInt8))
      ret = LibSSH2.sftp_read(self, slice, LibC::SizeT.new(slice.bytesize))
      check_error(ret)
      ret
    end

    def write(slice : Slice(UInt8))
      ret = LibSSH2.sftp_write(self, slice, LibC::SizeT.new(slice.bytesize))
      check_error(ret)
      ret
    end
  end
end
