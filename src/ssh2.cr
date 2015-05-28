require "./lib_ssh2"

module SSH2
  class SSH2Error < Exception; end

  class SessionError < SSH2Error
    def initialize(session)
      @code = LibSSH2.session_last_errno(session)
      LibSSH2.session_last_error(session, out errmsg, out errmsg_len, 0)
      @msg = String.new errmsg, errmsg_len
      super("#{@code}: #{@msg}")
    end

    def self.check_error(session, code)
      if code >= LibSSH2::ERROR_NONE || code == LibSSH2::ERROR_EAGAIN
        return code
      else
        raise SessionError.new(session)
      end
    end
  end

  unless (rc = LibSSH2.init(0)) == 0
    raise SSH2Error.new "failed to initialize libssh2 (#{rc})"
  end

  def self.version
    String.new LibSSH2.version(0)
  end
end

require "./session"
require "./channel"
require "./listener"
require "./agent"
