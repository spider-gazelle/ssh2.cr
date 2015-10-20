require "./base"

module SSH2::SFTP
  abstract class Node < Base
    getter sftp

    def initialize(@sftp, handle)
      super(@sftp.session, handle)
    end

    # Close an active SFTP instance.
    def close
      return if @closed
      @closed = true
      LibSSH2.sftp_close(@handle)
    end

    # Set file attributes
    def fstat=(value : Attributes)
      ret = LibSSH2.sftp_fstat(self, value, 1)
      check_error(ret)
    end

    # Get file attributes
    def fstat
      ret = LibSSH2.sftp_fstat(self, out value, 0)
      check_error(ret)
      Attributes.new value
    end

    def closed?
      @closed || @sftp.closed?
    end
  end
end
