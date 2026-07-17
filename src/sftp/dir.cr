require "./node"

module SSH2::SFTP
  class Dir
    include Node

    # Lists a current directory
    def ls(&)
      loop do
        buf_space = uninitialized UInt8[512]
        buf = buf_space.to_slice
        ret = @session.perform_nonblock { LibSSH2.sftp_readdir(self, buf, LibC::SizeT.new(buf.size), nil, LibC::SizeT.new(0), out attrs) }
        break if ret == 0
        yield String.new(buf[0, ret])
      end
    end

    # Lists a current directory
    def ls
      ret = [] of String
      ls { |file_name| ret << file_name }
      ret
    end

    # Lists the current directory in long form, yielding each entry's full
    # listing line (as returned by the server) when available, otherwise its name.
    def ll(&)
      loop do
        buf_space = uninitialized UInt8[512]
        buf = buf_space.to_slice
        lbuf_space = uninitialized UInt8[512]
        lbuf = lbuf_space.to_slice
        lbuf.to_unsafe.map!(lbuf.size) { 0_u8 }

        ret = @session.perform_nonblock { LibSSH2.sftp_readdir(self, buf, LibC::SizeT.new(buf.size), lbuf, LibC::SizeT.new(lbuf.size), out attrs) }
        break if ret == 0
        if lbuf[0] == 0_u8
          yield String.new(buf[0, ret])
        else
          yield String.new(lbuf.to_unsafe)
        end
      end
    end

    # Returns the current directory's long-form listing as an array.
    def ll
      ret = [] of String
      ll { |file_name| ret << file_name }
      ret
    end
  end
end
