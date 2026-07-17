# A server-side listener for reverse (remote) port forwarding, created by
# `Session#forward_listen`. Inbound connections are queued until `accept`ed.
class SSH2::Listener
  getter session : Session
  getter bound_port : Int32

  def initialize(@session, @handle : LibSSH2::Listener, @bound_port)
    raise SSH2Error.new "invalid handle" unless @handle
    @canceled = false
  end

  def canceled?
    @canceled
  end

  # Accept the next queued inbound connection, returning it as a `Channel`.
  def accept
    handle = session.nonblock_handle { LibSSH2.channel_forward_accept(self) }
    Channel.new(session, handle)
  end

  # Stop listening and tell the remote host to stop forwarding to this port.
  def cancel
    return if canceled?
    session.perform_nonblock { LibSSH2.channel_forward_cancel(self) }
    @canceled = true
  end

  def finalize
    return if canceled?
    @canceled = true
    # best-effort, no fiber-yielding I/O in the GC finalizer (see Session#finalize)
    LibSSH2.channel_forward_cancel(@handle)
  rescue
    nil
  end

  def to_unsafe
    @handle
  end
end
