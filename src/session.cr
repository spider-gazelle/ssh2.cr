require "socket"

class SSH2::Session
  getter socket

  @@callbacks_lock = Mutex.new
  @@callbacks = {} of UInt64 => Proc(String, String, String)

  def initialize(@socket : TCPSocket)
    @request_lock = Mutex.new

    # We need a way to look-up this object when performing interactive logins
    @handle = LibSSH2.session_init(nil, nil, nil, Pointer(Void).new(self.object_id))
    raise SSH2Error.new "unable to initialize session" unless @handle
    self.blocking = false
    handshake
  end

  @handle : Pointer(Void) = Pointer(Void).new(0)

  def self.connect(host : String, port = 22)
    socket = TCPSocket.new(host, port)
    new(socket)
  end

  def self.open(host : String, port = 22)
    TCPSocket.open(host, port) do |socket|
      session = new(socket)
      begin
        yield session
      ensure
        session.disconnect
      end
    end
  end

  private def waitsocket
    flags = block_directions
    @socket.wait_readable if flags.inbound?
    @socket.wait_writable if flags.outbound?
  end

  def perform_nonblock
    loop do
      result = @request_lock.synchronize { yield }
      code = if result.is_a?(Tuple)
               result[0]
             else
               result
             end
      if code == LibSSH2::ERROR_EAGAIN
        waitsocket
      else
        check_error(code)
        return result
      end
    end
  end

  def nonblock_handle
    loop do
      result = @request_lock.synchronize { yield }
      handle = if result.is_a?(Tuple)
                 result[0]
               else
                 result
               end
      code = LibSSH2.session_last_errno(self)
      if handle.null? && code == LibSSH2::ERROR_EAGAIN
        waitsocket
      else
        check_error(code)
        return result
      end
    end
  end

  # Begin transport layer protocol negotiation with the connected host.
  def handshake
    @socket.wait_readable
    @socket.wait_writable
    perform_nonblock { LibSSH2.session_handshake(@handle, @socket.fd) }
    @connected = true
  end

  # Login with username and password
  def login(username : String, password : String)
    @socket.wait_writable
    perform_nonblock { LibSSH2.userauth_password(@handle, username, username.bytesize.to_u32,
      password, password.bytesize.to_u32, nil) }
  end

  # Callbacks passed to c-code must not capture context
  INTERACTIVE_CB = Proc(UInt8*, Int32, UInt8*, Int32, Int32, Void*, LibSSH2::Password*, Void*, Void).new do |name, name_len, instruction, instruction_len, num_prompts, _prompts, responses, data|
    # This is the number of response structures we can fill
    if num_prompts > 0
      uname = name.null? ? "" : String.new(name, name_len)
      welcome = instruction.null? ? "" : String.new(instruction, instruction_len)

      # Obtain the details of the object that made the request (passed in the initializer)
      object_id = Pointer(Pointer(Void)).new(data.address)[0].address
      callback = @@callbacks_lock.synchronize { @@callbacks.delete object_id }

      if callback
        # Get the password from the callback
        password = callback.call(uname, welcome)

        # libSSH2 frees the password memory for us so we need to allocate it outside the GC
        pass_bytes = Pointer(UInt8).new(LibC.malloc(LibC::SizeT.new(password.bytesize)).address)
        password.to_slice.copy_to(pass_bytes, password.bytesize)

        # Extract the response structure that was passed in and configure it
        pass = responses[0]
        pass.password = pass_bytes
        pass.length = password.bytesize.to_u32

        # Write the bytes back to original address
        responses.move_from(pointerof(pass), 1)
      end
    end
    nil
  end

  # Login with an interactive password
  def interactive_login(username, &callback : Proc(String, String, String))
    # Capture the context of this request
    interactive_context = Proc(String, String, String).new do |uname, welcome|
      pass = callback.call(uname, welcome)
      @socket.wait_writable
      pass
    end

    # Save the context in a global
    @@callbacks_lock.synchronize { @@callbacks[self.object_id] = interactive_context }

    # Make the request
    @socket.wait_writable
    perform_nonblock do
      LibSSH2.userauth_keyboard_interactive(@handle, username, username.bytesize.to_u32, INTERACTIVE_CB)
    end
  ensure
    @@callbacks_lock.synchronize { @@callbacks.delete object_id }
  end

  private def password_cb(username : String, welcome : String) : String
    @interactive_cb.not_nil!.call(username, welcome)
  end

  # Login with username using pub/priv key values
  def login_with_data(username : String, privkey : String, pubkey : String, passphrase : String? = nil)
    @socket.wait_writable
    perform_nonblock { LibSSH2.userauth_publickey_frommemory(@handle, username, username.bytesize.to_u32,
      pubkey, LibC::SizeT.new(pubkey.bytesize),
      privkey, LibC::SizeT.new(privkey.bytesize),
      passphrase ? passphrase.to_slice.to_unsafe : Pointer(UInt8).null) }
  end

  # Login with username using pub/priv key files
  def login_with_pubkey(username : String, privkey : String, pubkey : String, passphrase : String? = nil)
    privkey = File.read(privkey)
    pubkey = File.read(pubkey)
    login_with_data(username, privkey, pubkey, passphrase ? passphrase.to_slice.to_unsafe : Pointer(UInt8).null)
  end

  # Login with username using SSH agent
  # Warning: this method will block the crystal lang event loop.
  # Not recommended outside of very small, limited purpose applications.
  def login_with_agent(username : String)
    agent = Agent.new(self)
    agent.connect
    begin
      agent.list_identities
      agent.authenticate(username)
    ensure
      agent.disconnect
    end
  end

  # Send a SSH_USERAUTH_NONE request to the remote host. Unless the remote host
  # is configured to accept none as a viable authentication scheme (unlikely),
  # it will return SSH_USERAUTH_FAILURE along with a listing of what
  # authentication schemes it does support. In the unlikely event that none
  # authentication succeeds, this method with return `nil`. This case may be
  # distinguished from a failing case by examining `authenticated?`.
  #
  # Returns false value if authentication was successfull, an array of supported
  # methods string or true otherwise
  def login_with_noauth(username : String)
    @socket.wait_writable
    handle = nonblock_handle { LibSSH2.userauth_list(@handle, username, username.bytesize.to_u32) }
    if handle
      String.new(handle).split(",")
    else
      !authenticated?
    end
  end

  # Indicates whether or not the named session has been successfully authenticated.
  def authenticated?
    LibSSH2.userauth_authenticated(self) == 1
  end

  # Returns the current session's host key
  def hashkey(type : LibSSH2::HashType = LibSSH2::HashType::SHA1)
    handle = LibSSH2.hostkey_hash(self, type)
    return "" unless handle
    slice = Slice.new(handle, type == LibSSH2::HashType::SHA1 ? 20 : 16)
    String.build do |o|
      slice.each_with_index do |b, idx|
        o << b.to_s(16)
        o << ":" unless idx == length - 1
      end
    end
  end

  # Send a disconnect message to the remote host associated with session, along
  # with a description.
  def disconnect(reason = LibSSH2::DisconnectReason::BY_APPLICATION, description = "bye")
    return unless @connected
    perform_nonblock { LibSSH2.session_disconnect(self, reason, description, "") }
  rescue
  ensure
    @socket.close
    @connected = false
  end

  # Once the session has been setup and `handshake` has completed successfully,
  # this function can be used to get the server id from the banner each server
  # presents.
  def banner
    String.new LibSSH2.session_banner_get(self)
  end

  # Set the banner that will be sent to the remote host when the SSH session is
  # started with `handshake`. This is optional; a banner corresponding to the
  # protocol and libssh2 version will be sent by default.
  def banner=(value)
    perform_nonblock { LibSSH2.session_banner_set(self, value) }
  end

  # Returns block direction flags
  def block_directions
    LibSSH2.session_block_directions(self)
  end

  # check whether the session is in blocking mode
  def blocking?
    LibSSH2.session_get_blocking(self) == 1
  end

  # Set or clear blocking mode on the selected on the session. This will
  # instantly affect any channels associated with this session. If a read is
  # performed on a session with no data currently available, a blocking session
  # will wait for data to arrive and return what it receives. A non-blocking
  # session will return immediately with an empty buffer. If a write is
  # performed on a session with no room for more data, a blocking session will
  # wait for room. A non-blocking session will return immediately without
  # writing anything.
  private def blocking=(value)
    LibSSH2.session_set_blocking(self, value ? 1 : 0)
  end

  # Returns the timeout (in milliseconds) for how long a blocking the libssh2
  # function calls may wait until they consider the situation an error and
  # raise an exception
  def timeout
    LibSSH2.session_get_timeout(self)
  end

  # Set the timeout in milliseconds for how long a blocking the libssh2
  # function calls may wait until they consider the situation an error and
  # raise an exception.
  def timeout=(value)
    LibSSH2.session_set_timeout(self, value.to_i64)
  end

  # If set, libssh2 will not attempt to block SIGPIPEs but will let them trigger from the underlying socket layer.
  def set_enable_sigpipe(value)
    perform_nonblock { LibSSH2.session_flag(self, LibSSH2::SessionFlag::SIGPIPE, value ? 1 : 0) }
  end

  # If set - before the connection negotiation is performed - libssh2 will try
  # to negotiate compression enabling for this connection. By default libssh2
  # will not attempt to use compression.
  def set_enable_compression(value)
    perform_nonblock { LibSSH2.session_flag(self, LibSSH2::SessionFlag::COMPRESS, value ? 1 : 0) }
  end

  # Returns a tuple consisting of the computed digest of the remote system's
  # hostkey and its type.
  def hostkey
    handle = LibSSH2.session_hostkey(self, out len, out ty)
    raise SSH2Error.new "unable to obtain hostkey" unless handle
    {Slice.new(handle, len.to_i32), LibSSH2::HostKeyType.new(ty)}
  end

  # Set preferred methods to be negotiated. These preferences must be set prior
  # to calling `handshake`, as they are used during the protocol initiation
  # phase.
  def set_method_pref(method_type : LibSSH2::MethodType, value)
    perform_nonblock { LibSSH2.session_method_pref(self, method_type, value) }
  end

  # Returns the actual method negotiated for a particular transport parameter.
  def method_pref(method_pref : LibSSH2::MethodType)
    handle = LibSSH2.session_methods(self, method_type)
    String.new handle unless handle
  end

  # Get a list of supported algorithms for the given method_type.
  def supported_algs(method_type : LibSSH2::MethodType)
    ret = [] of String
    if (count = LibSSH2.session_supported_algs(self, method_type, out algs)) > 0
      count.times do |i|
        ret << String.new(algs[i])
      end
    end
    ret
  end

  # Send a keepalive message if needed.
  # Return value indicates how many seconds you can sleep after this call
  # before you need to call it again.
  def send_keepalive
    _, seconds = perform_nonblock do
      code = LibSSH2.keepalive_send(self, out seconds_to_next)
      {code, seconds_to_next}
    end
    seconds
  end

  # Return `KnownHosts` object that allows managing known hosts
  def knownhosts
    KnownHosts.new(self)
  end

  # Instruct the remote SSH server to begin listening for inbound TCP/IP
  # connections. New connections will be queued by the library until accepted
  # by `Listener.accept`.
  def forward_listen(host, port, queue_maxsize = 16)
    handle, bport = nonblock_handle do
      ret = LibSSH2.channel_forward_listen(self, host, port, out bound_port, queue_maxsize)
      {ret, bound_port}
    end
    Listener.new(self, handle, bport)
  end

  # Allocate a new channel for exchanging data with the server.
  def open_channel(channel_type, window_size, packet_size, message)
    handle = nonblock_handle { LibSSH2.channel_open(self, channel_type, channel_type.bytesize.to_u32,
      window_size.to_u32, packet_size.to_u32,
      message, message ? message.bytesize.to_u32 : 0_u32) }
    Channel.new self, handle
  end

  # Open new session channel
  def open_session
    open_channel("session", LibSSH2::CHANNEL_WINDOW_DEFAULT, LibSSH2::CHANNEL_PACKET_DEFAULT, nil)
  end

  def open_session
    channel = open_session
    begin
      yield channel
    ensure
      channel.close
    end
  end

  # Tunnel a TCP/IP connection through the SSH transport via the remote host to
  # a third party. Communication from the client to the SSH server remains
  # encrypted, communication from the server to the 3rd party host travels in
  # cleartext.
  def direct_tcpip(host, port, source_host, source_port)
    handle = nonblock_handle { LibSSH2.channel_direct_tcpip(self, host, port, source_host, source_port) }
    Channel.new self, handle
  end

  def direct_tcpip(host, port, source_host, source_port)
    channel = direct_tcpip(host, port, source_host, source_port)
    begin
      yield channel
    ensure
      channel.close
    end
  end

  # Send a file to the remote host via SCP.
  def scp_send(path, mode, size, mtime, atime)
    handle = nonblock_handle { LibSSH2.scp_send(self, path, mode.to_i32, size.to_u64,
      LibC::TimeT.new(mtime), LibC::TimeT.new(atime)) }
    Channel.new self, handle
  end

  # Send a file to the remote host via SCP.
  # A new channel is passed to the block and closed afterwards.
  def scp_send(path, mode, size, mtime = Time.utc.to_unix, atime = Time.utc.to_unix)
    channel = scp_send(path, mode, size, mtime, atime)
    begin
      yield channel
    ensure
      channel.close
    end
  end

  # Send a file from a local filesystem to the remote host via SCP.
  def scp_send_file(path, remote_path = path)
    if LibC.stat(path, out stat) != 0
      raise SSH2Error.new("Unable to get stat for '#{path}'")
    end
    scp_send(remote_path, (stat.st_mode & 0x3ff).to_i32, stat.st_size.to_u64,
      stat.st_mtim.tv_sec, stat.st_atim.tv_sec) do |ch|
      File.open(path, "r") do |f|
        IO.copy(f, ch)
      end
    end
  end

  # Request a file from the remote host via SCP.
  def scp_recv(path)
    handle, stats = nonblock_handle do
      ret = LibSSH2.scp_recv(self, path, out stat)
      {ret, stat}
    end
    {Channel.new(self, handle), stats}
  end

  # Request a file from the remote host via SCP.
  # A new channel is passed to the block and closed afterwards.
  def scp_recv(path)
    channel, stat = scp_recv(path)
    begin
      yield channel, stat
    ensure
      channel.close
    end
  end

  # Download a file from the remote host via SCP to the local filesystem.
  def scp_recv_file(path, local_path = path)
    File.open(local_path, "w") do |f|
      scp_recv(path) do |ch, st|
        buf = Slice(UInt8).new(st.st_size.to_i32)
        ch.read(buf)
        f.write(buf)
      end
    end
  end

  # Open a channel and initialize the SFTP subsystem.
  # Returns a new SFTP instance
  def sftp_session
    handle = nonblock_handle { LibSSH2.sftp_init(self) }
    SFTP::Session.new(self, handle)
  end

  def sftp_session
    sftp = sftp_session
    begin
      yield sftp
    ensure
      sftp.close
    end
  end

  # Set the trace option. Only available if libssh2 is compliled with debug mode.
  def trace(bitmask : LibSSH2::Trace)
    LibSSH2.trace(self, bitmask)
  end

  def finalize
    disconnect if @connected
    # Prevents a memory leak: https://github.com/libssh2/libssh2/issues/282
    LibSSH2.session_handshake(@handle, @socket.fd)
    LibSSH2.session_free(self)
  end

  private def check_error(code)
    SessionError.check_error(self, code)
  end

  def to_unsafe
    @handle
  end
end
