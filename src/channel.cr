require "./session"

class SSH2::Channel < IO

  PROCESS_SHELL = "shell"
  PROCESS_EXEC = "exec"
  PROCESS_SUBSYSTEM = "subsystem"

  getter session : Session

  def initialize(@session, @handle : LibSSH2::Channel, @owned = true)
    raise SSH2Error.new "invalid handle" unless @handle
    @closed = false
  end

  def socket
    @session.socket.not_nil!
  end

  # Close an active data channel. In practice this means sending an
  # SSH_MSG_CLOSE packet to the remote host which serves as instruction that no
  # further data will be sent to it. The remote host may still send data back
  # until it sends its own close message in response. To wait for the remote
  # end to close its connection as well, follow this command with
  # `wait_closed` or pass `wait` parameter as true.
  def close(wait = false)
    return if @closed
    ret = LibSSH2.channel_close(self)
    check_error(ret).tap do
      @closed = true
      wait_closed if wait
    end
  end

  def closed?
    @closed
  end

  def wait_closed
    ret = LibSSH2.channel_wait_closed(self)
    check_error(ret)
  end

  # Check if the remote host has sent an EOF status for the selected stream.
  def eof?
    LibSSH2.channel_eof(self) == 1
  end

  # Start shell
  def shell
    process_startup(PROCESS_SHELL, nil)
  end

  # Start a specified command
  def command(command)
    process_startup(PROCESS_EXEC, command)
  end

  # Start a specified subsystem
  def subsystem(subsystem)
    process_startup(PROCESS_SUBSYSTEM, subsystem)
  end

  def process_startup(request, message)
    ret = LibSSH2.channel_process_startup(self, request, request.bytesize.to_u32,
                                          message, message ? message.bytesize.to_u32 : 0_u32)
    check_error(ret)
  end

  # Return a tuple with first field populated with the exit signal (without
  # leading "SIG"), and the second field populated with the error message.
  def exit_signal
    ret = LibSSH2.channel_get_exit_signal(self, out exitsignal, out exitsignal_len,
                                          out errmsg, out errmsg_len, nil, nil)
    check_error(ret)
    exitsignal_str = String.new(exitsignal, exitsignal_len) if exitsignal
    errmsg_str = String.new(errmsg, errmsg_len) if errmsg
    {exitsignal_str, errmsg_str}
  end

  # Returns the exit code raised by the process running on the remote host at
  # the other end of the named channel. Note that the exit status may not be
  # available if the remote end has not yet set its status to closed.
  def exit_status
    LibSSH2.channel_get_exit_status(self)
  end

  # LibSSH2::ExtendedData::NORMAL - Queue extended data for eventual reading
  # LibSSH2::ExtendedData::MERGE  - Treat extended data and ordinary data the
  # same. Merge all substreams such that calls to `read`, will pull from all
  # substreams on a first-in/first-out basis.
  # LibSSH2::ExtendedData::IGNORE - Discard all extended data as it arrives.
  def handle_extended_data(ignore_mode : LibSSH2::ExtendedData)
    ret = LibSSH2.channel_handle_extended_data(self, ignore_mode)
    check_error(ret)
  end

  def read(stream_id, slice : Slice(UInt8))
    ret = LibSSH2.channel_read(self, stream_id, slice, LibC::SizeT.new(slice.bytesize))
    check_error(ret)
  end

  def write(stream_id, slice : Slice(UInt8))
    ret = LibSSH2.channel_write(self, stream_id, slice, LibC::SizeT.new(slice.bytesize))
    check_error(ret)
  end

  def read(slice : Slice(UInt8))
    return 0 if eof?
    read(0, slice)
  end

  def write(slice : Slice(UInt8))
    write(0, slice)
  end

  def read_stderr(slice : Slice(UInt8))
    read(LibSSH2::SSH_EXTENDED_DATA_STDERR, slice)
  end

  def write_stderr(slice : Slice(UInt8))
    write(LibSSH2::SSH_EXTENDED_DATA_STDERR, slice)
  end

  # Flush channel
  def flush(stream_id = 0)
    ret = LibSSH2.channel_flush(self, stream_id)
    check_error(ret)
  end

  # Flush stderr
  def flush_stderr
    flush(LibSSH2::SSH_EXTENDED_DATA_STDERR)
  end

  # Flush all substreams
  def flush_all
    flush(LibSSH2::CHANNEL_FLUSH_ALL)
  end

  # Flush all extended data substreams
  def flush_extended_data
    flush(LibSSH2::CHANNEL_FLUSH_EXTENDED_DATA)
  end

  def err_stream
    StreamIO.new(self, LibSSH2::SSH_EXTENDED_DATA_STDERR)
  end

  def stream(stream_id)
    StreamIO.new(self, stream_id)
  end

  # Adjust the receive window for a channel by adjustment bytes. If the amount
  # to be adjusted is less than `LibSSH2::CHANNEL_MINADJUST` and force is false the
  # adjustment amount will be queued for a later packet.
  # Returns a new size of the receive window (as understood by remote end).
  def receive_window_adjust(adjustment, force = false)
    ret = LibSSH2.channel_receive_window_adjust(self, adjustment, force ? 1_u8 : 0_u8, out window)
    check_error(ret)
    window
  end

  # Request a PTY on an established channel. Note that this does not make sense
  # for all channel types and may be ignored by the server despite returning
  # success.
  def request_pty(term, modes = nil, width = LibSSH2::TERM_WIDTH, height = LibSSH2::TERM_HEIGHT,
                  width_px = LibSSH2::TERM_WIDTH_PX, height_px = LibSSH2::TERM_HEIGHT_PX)
    ret = LibSSH2.channel_request_pty(self, term, term.bytesize.to_u32,
                                      modes, modes ? modes.bytesize.to_u32 : 0_u32,
                                      width, height, width_px, height_px)
    check_error(ret)
  end

  # Tell the remote host that no further data will be sent on the specified
  # channel. Processes typically interpret this as a closed stdin descriptor.
  def send_eof(wait = false)
    ret = LibSSH2.channel_send_eof(self)
    check_error(ret).tap do
      wait_eof if wait
    end
  end

  # Wait for the remote end to acknowledge an EOF request.
  def wait_eof
    ret = LibSSH2.channel_wait_eof(self)
    check_error(ret)
  end

  # Set an environment variable in the remote channel's process space. Note
  # that this does not make sense for all channel types and may be ignored by
  # the server despite returning success.
  def setenv(varname, value)
    ret = LibSSH2.channel_setenv(self, varname, varname.bytesize.to_u32, value, value.bytesize.to_u32)
    check_error(ret)
  end

  # The number of bytes which the remote end may send without overflowing the window limit
  def window_read
    LibSSH2.channel_window_read(self, nil, nil)
  end

  # Check the status of the write window Returns the number of bytes which may
  # be safely written on the channel without blocking.
  def window_write
    LibSSH2.channel_window_write(self, nil)
  end

  def finalize
    LibSSH2.channel_free(@handle) if @owned
  end

  def to_unsafe
    @handle
  end

  private def check_error(code)
    SessionError.check_error(@session, code)
  end

  class StreamIO < IO

    getter channel : Channel
    getter stream_id : Int32

    def initialize(@channel, @stream_id)
    end

    def read(slice : Slice(UInt8))
      @channel.read(@stream_id, slice)
    end

    def write(slice : Slice(UInt8))
      @channel.write(@stream_id, slice)
    end

    def flush
      @channel.flush(@stream_id)
    end
  end
end
