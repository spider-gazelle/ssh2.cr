abstract class SSH2::SFTP::Base
  def initialize(@session, @handle)
    raise SSH2Error.new "invalid handle" unless @handle
    @closed = false
  end

  def closed?
    @closed
  end

  def to_unsafe
    @handle
  end

  protected def check_error(code)
    SessionError.check_error(@session, code)
  end

  def finalize
    close unless @closed
  end
end
