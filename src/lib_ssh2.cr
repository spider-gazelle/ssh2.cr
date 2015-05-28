@[Link("ssh2")]
lib LibSSH2
  alias Session = Void*

  INIT_NO_CRYPTO = 0x0001
  fun init = libssh2_init(flags: Int32) : Int32
  fun exit = libssh2_exit()
  fun free = libssh2_free(session: Session, ptr: Void*)
  fun version = libssh2_version(req_version: Int32) : UInt8*

  @[Flags]
  enum BlockDirections
    Inbound,
    Outbound
  end

  enum CallbackType
    IGNORE     = 0
    DEBUG      = 1
    DISCONNECT = 2
    MACERROR   = 3
    X11        = 4
    SEND       = 5
    RECV       = 6
  end

  enum SessionFlag
    SIGPIPE  = 1
    COMPRESS = 2
  end

  enum MethodType
    KEX      = 0
    HOSTKEY  = 1
    CRYPT_CS = 2
    CRYPT_SC = 3
    MAC_CS   = 4
    MAC_SC   = 5
    COMP_CS  = 6
    COMP_SC  = 7
    LANG_CS  = 8
    LANG_SC  = 9
  end

  enum HostKeyType
    UNKNOWN = 0
    RSA     = 1
    DSS     = 2
  end

  enum DisconnectReason
    HOST_NOT_ALLOWED_TO_CONNECT    = 1
    PROTOCOL_ERROR                 = 2
    KEY_EXCHANGE_FAILED            = 3
    RESERVED                       = 4
    MAC_ERROR                      = 5
    COMPRESSION_ERROR              = 6
    SERVICE_NOT_AVAILABLE          = 7
    PROTOCOL_VERSION_NOT_SUPPORTED = 8
    HOST_KEY_NOT_VERIFIABLE        = 9
    CONNECTION_LOST                = 10
    BY_APPLICATION                 = 11
    TOO_MANY_CONNECTIONS           = 12
    AUTH_CANCELLED_BY_USER         = 13
    NO_MORE_AUTH_METHODS_AVAILABLE = 14
    ILLEGAL_USER_NAME              = 15
  end

  ERROR_NONE   = 0
  ERROR_EAGAIN = -37

  fun session_init = libssh2_session_init_ex(alloc: Void*, free: Void*, realloc: Void*, user_data: Void*) : Session
  fun session_free = libssh2_session_free(session: Session) : Int32
  fun session_handshake = libssh2_session_handshake(session: Session, socket: Int32) : Int32
  fun session_banner_get = libssh2_session_banner_get(session: Session) : UInt8*
  fun session_banner_set = libssh2_session_banner_set(session: Session, banner: UInt8*) : Int32
  fun session_block_directions = libssh2_session_block_directions(session: Session) : BlockDirections
  fun session_callback_set = libssh2_session_callback_set(session: Session, cbtype: CallbackType, cb: Void*) : Void*
  fun session_disconnect = libssh2_session_disconnect_ex(session: Session, reason: DisconnectReason,
                                                         description: UInt8*, lang: UInt8*) : Int32
  fun session_flag = libssh2_session_flag(session: Session, flag: SessionFlag, value: Int32) : Int32
  fun session_get_blocking = libssh2_session_get_blocking(session: Session) : Int32
  fun session_get_timeout = libssh2_session_get_timeout(session: Session) : Int64
  fun session_hostkey = libssh2_session_hostkey(session: Session, len: LibC::SizeT*, type: Int32*) : UInt8*
  fun session_last_errno = libssh2_session_last_errno(session: Session) : Int32
  fun session_last_error = libssh2_session_last_error(session: Session, errmsg: UInt8**, errmsg_len: Int32*, want_buf: Int32) : Int32
  fun session_method_pref = libssh2_session_method_pref(session: Session, type: MethodType, prefs: UInt8*) : Int32
  fun session_methods = libssh2_session_methods(session: Session, type: MethodType) : UInt8*
  fun session_set_blocking = libssh2_session_set_blocking(session: Session, blocking: Int32)
  fun session_set_timeout = libssh2_session_set_timeout(session: Session, timeout: Int64)
  fun session_supported_algs = libssh2_session_supported_algs(session: Session, type: MethodType, algs: UInt8***) : Int32

  enum HashType
    MD5  = 1
    SHA1 = 2
  end

  fun hostkey_hash = libssh2_hostkey_hash(session: Session, type: HashType) : UInt8*

  fun userauth_authenticated = libssh2_userauth_authenticated(session: Session) : Int32
  fun userauth_hostbased_fromfile = libssh2_userauth_hostbased_fromfile_ex(session: Session, username: UInt8*, username_len: UInt32,
                                                                           pubkey: UInt8*, prvkey: UInt8*, passphrase: UInt8*,
                                                                           host: UInt8*, host_len: UInt32, localuser: UInt8*,
                                                                           localuser_len: UInt32) : Int32
  fun userauth_list = libssh2_userauth_list(session: Session, username: UInt8*, username_len: UInt32) : UInt8*

  alias PasswordChangeCallback = (Session, UInt8**, Int32*, Void**) -> Int32

  fun userauth_password = libssh2_userauth_password_ex(session: Session, username: UInt8*, username_len: UInt32,
                                                       password: UInt8*, password_len: UInt32, cb: PasswordChangeCallback) : Int32
  fun userauth_publickey_fromfile = libssh2_userauth_publickey_fromfile_ex(session: Session, username: UInt8*, username_len: UInt32,
                                                                           pubkey: UInt8*, privkey: UInt8*, passphrase: UInt8*) : Int32
  fun userauth_publickey_frommemory = libssh2_userauth_publickey_frommemory(session: Session, username: UInt8*, username_len: UInt32,
                                                                            pubkey: UInt8*, pubkey_len: LibC::SizeT,
                                                                            prvkey: UInt8*, prvkey_len: LibC::SizeT,
                                                                            passphrase: UInt8*) : Int32

  fun keepalive_config = libssh2_keepalive_config(session: Session, want_reply: Int32, interval: UInt32)
  fun keepalive_send = libssh2_keepalive_send(session: Session, seconds_to_next: Int32*) : Int32

  alias KnownHosts = Void*

  @[Flags]
  enum TypeMask
    PLAIN         = 1
    SHA1          = 2
    CUSTOM        = 3

    KEYENC_MASK   = (3<<16)
    KEYENC_RAW    = (1<<16)
    KEYENC_BASE64 = (2<<16)

    KEY_MASK      = (7<<18)
    KEY_SHIFT     = 18
    KEY_RSA1      = (1<<18)
    KEY_SSHRSA    = (2<<18)
    KEY_SSHDSS    = (3<<18)
    KEY_UNKNOWN   = (7<<18)
  end

  enum KnownHostCheck
    MATCH    = 0
    MISMATCH = 1
    NOTFOUND = 2
    FAILURE  = 3
  end

  struct KnownHost
    magic: UInt32
    node: Void*
    name: UInt8*
    key: UInt8*
    typemask: TypeMask
  end

  KNOWNHOST_FILE_OPENSSH = 1

  fun knownhost_init = libssh2_knownhost_init(session: Session) : KnownHosts
  fun knownhost_free = libssh2_knownhost_free(kh: KnownHosts)
  fun knownhost_add = libssh2_knownhost_addc(kh: KnownHosts, host: UInt8*, salt: UInt8*, key: UInt8*, keylen: LibC::SizeT,
                                            comment: UInt8*, commentlen: LibC::SizeT, typemask: TypeMask,
                                            store: KnownHost**) : Int32
  fun knownhost_check = libssh2_knownhost_check(kh: KnownHosts, host: UInt8*, key: UInt8*, keylen: LibC::SizeT,
                                                typemask: TypeMask, store: KnownHost**) : KnownHostCheck
  fun knownhost_checkp = libssh2_knownhost_checkp(kh: KnownHosts, host: UInt8*, port: Int32, key: UInt8*, keylen: LibC::SizeT,
                                                  typemask: TypeMask, store: KnownHost**) : KnownHostCheck
  fun knownhost_get = libssh2_knownhost_get(kh: KnownHosts, store: KnownHost**, prev: KnownHost*) : Int32
  fun knownhost_del = libssh2_knownhost_del(kh: KnownHosts, entry: KnownHost*) : Int32
  fun knownhost_readfile = libssh2_knownhost_readfile(kh: KnownHosts, filename: UInt8*, type: Int32) : Int32
  fun knownhost_readline = libssh2_knownhost_readline(kh: KnownHosts, line: UInt8*, len: LibC::SizeT, type: Int32) : Int32
  fun knownhost_writefile = libssh2_knownhost_writefile(kh: KnownHosts, filename: UInt8*, type: Int32) : Int32
  fun knownhost_writeline = libssh2_knownhost_writeline(kh: KnownHosts, known: KnownHost*, buffer: UInt8*, buflen: LibC::SizeT,
                                                        outlen: LibC::SizeT*, type: Int32) : Int32

  alias Channel = Void*

  SSH_EXTENDED_DATA_STDERR            = 1
  CHANNEL_FLUSH_EXTENDED_DATA = -1
  CHANNEL_FLUSH_ALL           = -2

  CHANNEL_MINADJUST      = 1024
  CHANNEL_WINDOW_DEFAULT = (2*1024*1024)
  CHANNEL_PACKET_DEFAULT = 32768

  enum ExtendedData
    NORMAL = 0
    IGNORE = 1
    MERGE  = 2
  end

  fun channel_free = libssh2_channel_free(ch: Channel) : Int32
  fun channel_open = libssh2_channel_open_ex(session: Session, channel_type: UInt8*, channel_type_len: UInt32,
                                             window_size: UInt32, packet_size: UInt32, message: UInt8*,
                                             message_len: UInt32) : Channel
  fun channel_direct_tcpip = libssh2_channel_direct_tcpip_ex(session: Session, host: UInt8*, port: Int32,
                                                             shost: UInt8*, sport: Int32) : Channel
  fun channel_close = libssh2_channel_close(ch: Channel): Int32
  fun channel_eof = libssh2_channel_eof(ch: Channel) : Int32
  fun channel_process_startup = libssh2_channel_process_startup(ch: Channel, request: UInt8*, request_len: UInt32,
                                                                message: UInt8*, message_len: UInt32) : Int32
  fun channel_flush = libssh2_channel_flush_ex(ch: Channel, stream_id: Int32) : Int32
  fun channel_get_exit_signal = libssh2_channel_get_exit_signal(ch: Channel, exitsignal: UInt8**, exitsignal_len: LibC::SizeT*,
                                                                errmsg: UInt8**, errmsg_len: LibC::SizeT*,
                                                                langtag: UInt8**, langtag_len: LibC::SizeT*) : Int32
  fun channel_get_exit_status = libssh2_channel_get_exit_status(ch: Channel) : Int32
  fun channel_handle_extended_data = libssh2_channel_handle_extended_data2(ch: Channel, extended_data: ExtendedData) : Int32
  fun channel_read = libssh2_channel_read_ex(ch: Channel, stream_id: Int32, buf: UInt8*, buflen: LibC::SizeT) : LibC::SSizeT
  fun channel_write = libssh2_channel_write_ex(ch: Channel, stream_id: Int32, buf: UInt8*, buflen: LibC::SizeT) : LibC::SSizeT
  fun channel_receive_window_adjust = libssh2_channel_receive_window_adjust2(ch: Channel, adj: UInt64, force: UInt8,
                                                                             window: UInt32*) : Int32
  fun channel_request_pty = libssh2_channel_request_pty_ex(ch: Channel, term: UInt8*, term_len: UInt32, modes: UInt8*, modes_len: UInt32,
                                                           width: Int32, height: Int32, width_px: Int32, height_px: Int32) : Int32
  fun channel_send_eof = libssh2_channel_send_eof(ch: Channel) : Int32
  fun channel_setenv = libssh2_channel_setenv_ex(ch: Channel, varname: UInt8*, varname_len: UInt32,
                                                 value: UInt8*, value_len: UInt32) : Int32
  fun channel_wait_closed = libssh2_channel_wait_closed(ch: Channel) : Int32
  fun channel_wait_eof = libssh2_channel_wait_eof(ch: Channel) : Int32
  fun channel_window_read = libssh2_channel_window_read_ex(ch: Channel, read_avail: UInt64*, window_size_initial: UInt64*) : UInt64
  fun channel_window_write = libssh2_channel_window_write_ex(ch: Channel, window_size_initial: UInt64*) : UInt64

  alias Listener = Void*

  fun channel_forward_listen = libssh2_channel_forward_listen_ex(session: Session, host: UInt8*, port: Int32, bound_port: Int32*,
                                                                 queue_maxsize: Int32) : Listener
  fun channel_forward_accept = libssh2_channel_forward_accept(listener: Listener) : Channel
  fun channel_forward_cancel = libssh2_channel_forward_cancel(listener: Listener) : Int32

  alias Agent = Void*
  struct AgentPublicKey
    magic: UInt32
    node: Void*
    blob: UInt8*
    blob_len: LibC::SizeT
    comment: UInt8*
  end

  fun agent_init = libssh2_agent_init(session: Session) : Agent
  fun agent_free = libssh2_agent_free(agent: Agent)
  fun agent_connect = libssh2_agent_connect(agent: Agent) : Int32
  fun agent_disconnect = libssh2_agent_disconnect(agent: Agent) : Int32
  fun agent_get_identity = libssh2_agent_get_identity(agent: Agent, store: AgentPublicKey**, prev: AgentPublicKey*) : Int32
  fun agent_list_identities = libssh2_agent_list_identities(agent: Agent) : Int32
  fun agent_userauth = libssh2_agent_userauth(agent: Agent, username: UInt8*, identity: AgentPublicKey*) : Int32

  fun scp_recv = libssh2_scp_recv(session: Session, path: UInt8*, stat: LibC::Stat*) : Channel
  fun scp_send = libssh2_scp_send64(session: Session, path: UInt8*, mode: Int32, size: UInt64,
                                     mtime: LibC::TimeT, atime: LibC::TimeT) : Channel
end
