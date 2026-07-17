require "./node"

module SSH2::SFTP
  class File < IO
    include Node

    # This function causes the remote server to synchronize the file data and
    # metadata to disk (like fsync(2)).
    def fsync
      @session.perform_nonblock { LibSSH2.sftp_fsync(self) }
    end

    # Move the read/write position to `offset` bytes from the start of the file.
    def seek(offset)
      LibSSH2.sftp_seek(self, offset.to_u64)
    end

    # Reset the read/write position to the start of the file.
    def rewind
      seek(0)
    end

    # Return the current read/write position, in bytes from the start.
    def tell
      LibSSH2.sftp_tell(self)
    end

    def read(slice : Slice(UInt8)) : Int32
      @session.perform_nonblock { LibSSH2.sftp_read(self, slice, LibC::SizeT.new(slice.bytesize)) }.to_i32
    end

    # sftp_write can write less than we asked. loop until slice is done.
    # n == 0 is allowed by libssh2 (buffered, not acked). yield so we don't spin.
    {% if compare_versions(Crystal::VERSION, "0.35.0") == 0 %}
      def write(slice : Bytes) : Int64
        written = 0_i64
        while written < slice.bytesize
          remainder = slice + written
          n = @session.perform_nonblock { LibSSH2.sftp_write(self, remainder, LibC::SizeT.new(remainder.bytesize)) }
          if n == 0
            Fiber.yield
          else
            written += n.to_i64
          end
        end
        written
      end
    {% else %}
      def write(slice : Bytes) : Nil
        written = 0
        while written < slice.bytesize
          remainder = slice + written
          n = @session.perform_nonblock { LibSSH2.sftp_write(self, remainder, LibC::SizeT.new(remainder.bytesize)) }
          if n == 0
            Fiber.yield
          else
            written += n.to_i32
          end
        end
      end
    {% end %}
  end
end
