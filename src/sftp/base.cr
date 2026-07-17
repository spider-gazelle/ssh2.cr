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
    return if @closed
    @closed = true
    # best-effort, no fiber-yielding I/O in the GC finalizer (see Session#finalize)
    LibSSH2.sftp_shutdown(@handle)
  rescue
    nil
  end
end
