class SSH2::Listener
  getter session
  getter bound_port

  def initialize(@session, @handle : LibSSH2::Listener, @bound_port)
    raise SSH2Error.new "invalid handle" unless @handle
    @canceled = false
  end

  def canceled?
    @canceled
  end

  def accept
    Channel.new session, LibSSH2.channel_forward_accept(self)
  end

  def cancel
    return if canceled?
    ret = LibSSH2.channel_forward_cancel(self)
    SessionError.check_error(@session, ret)
    @canceled = true
  end

  def finalize
    cancel unless canceled?
  end

  def to_unsafe
    @handle
  end
end

