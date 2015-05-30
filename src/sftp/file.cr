module SSH2::SFTP
  class File < Base
    include IO

    # Close an active SFTP instance.
    def close
      return if @closed
      @closed = true
      LibSSH2.sftp_close(self)
    end

    # Set file attributes
    def fstat=(value: Attributes)
      ret = LibSSH2.sftp_fstat(self, value, 1)
      check_error(ret)
    end

    # Get file attributes
    def fstat
      ret = LibSSH2.sftp_fstat(self, out value, 0)
      check_error(ret)
      Attributes.new value
    end

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

    def read(slice: Slice(UInt8), length)
      ret = LibSSH2.sftp_read(self, slice.pointer(length), LibC::SizeT.cast(length))
      check_error(ret)
      ret
    end

    def write(slice: Slice(UInt8), length)
      ret = LibSSH2.sftp_write(self, slice.pointer(length), LibSSH2::SizeT.cast(length))
      check_error(ret)
      ret
    end
  end
end
