require "./node"

module SSH2::SFTP
  class File < IO
    include Node

    # This function causes the remote server to synchronize the file data and
    # metadata to disk (like fsync(2)).
    def fsync
      @session.perform_nonblock { LibSSH2.sftp_fsync(self) }
    end

    def seek(offset)
      LibSSH2.sftp_seek(self, offset.to_u64)
    end

    def rewind
      seek(0)
    end

    def tell
      LibSSH2.sftp_tell(self)
    end

    def read(slice : Slice(UInt8))
      @session.perform_nonblock { LibSSH2.sftp_read(self, slice, LibC::SizeT.new(slice.bytesize)) }
    end

    {% if compare_versions(Crystal::VERSION, "0.35.0") == 0 %}
      def write(slice : Bytes) : Int64
        @session.perform_nonblock { LibSSH2.sftp_write(self, slice, LibC::SizeT.new(slice.bytesize)) }
      end
    {% else %}
      def write(slice : Bytes) : Nil
        @session.perform_nonblock { LibSSH2.sftp_write(self, slice, LibC::SizeT.new(slice.bytesize)) }
      end
    {% end %}
  end
end
