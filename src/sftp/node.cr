require "./base"
require "./session"

module SSH2::SFTP
  module Node
    include Base

    def initialize(@sftp : Session, handle)
      super(@sftp.session, handle)
    end

    # Close an active SFTP instance.
    def close
      return if @closed
      @closed = true
      @session.perform_nonblock { LibSSH2.sftp_close(@handle) }
    end

    # Set file attributes
    def fstat=(value : Attributes)
      @session.perform_nonblock { LibSSH2.sftp_fstat(self, value, 1) }
    end

    # Get file attributes
    def fstat
      _, val = @session.perform_nonblock do
        ret = LibSSH2.sftp_fstat(self, out value, 0)
        {ret, value}
      end
      Attributes.new val
    end

    def closed?
      @closed || @sftp.closed?
    end

    def finalize
      return if closed?

      close rescue nil
    end
  end
end
