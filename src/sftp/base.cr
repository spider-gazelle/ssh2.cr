require "../session"
require "../lib_ssh2"

module SSH2::SFTP::Base
  getter session : SSH2::Session
  @handle : LibSSH2::SFTP

  def initialize(@session, @handle)
    raise SSH2Error.new "invalid handle" unless @handle
    @closed = false
  end

  def closed?
    @closed
  end

  def to_unsafe
    if closed?
      raise SFTPClosed.new
    end
    @handle
  end

  protected def check_error(code)
    SessionError.check_error(@session, code)
  end

  def finalize
    close unless @closed
  end
end
