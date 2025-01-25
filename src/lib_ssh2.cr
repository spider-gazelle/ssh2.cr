@[Link("ssh2", pkg_config: "libssh2")]
lib LibSSH2
  alias Session = Void*

  INIT_NO_CRYPTO = 0x0001
  fun init = libssh2_init(flags : Int32) : Int32
  fun exit = libssh2_exit
  fun free = libssh2_free(session : Session, ptr : Void*)
  fun version = libssh2_version(req_version : Int32) : UInt8*

  @[Flags]
  enum BlockDirections
    Inbound
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

  # https://github.com/libssh2/libssh2/blob/6c7769dcc422250d14af1b06fce378b6ee009440/include/libssh2.h#L423
  enum HostKeyType
    UNKNOWN   = 0
    RSA       = 1
    DSS       = 2
    ECDSA_256 = 3
    ECDSA_384 = 4
    ECDSA_521 = 5
    ED25519   = 6
  end

  enum DisconnectReason
    HOST_NOT_ALLOWED_TO_CONNECT    =  1
    PROTOCOL_ERROR                 =  2
    KEY_EXCHANGE_FAILED            =  3
    RESERVED                       =  4
    MAC_ERROR                      =  5
    COMPRESSION_ERROR              =  6
    SERVICE_NOT_AVAILABLE          =  7
    PROTOCOL_VERSION_NOT_SUPPORTED =  8
    HOST_KEY_NOT_VERIFIABLE        =  9
    CONNECTION_LOST                = 10
    BY_APPLICATION                 = 11
    TOO_MANY_CONNECTIONS           = 12
    AUTH_CANCELLED_BY_USER         = 13
    NO_MORE_AUTH_METHODS_AVAILABLE = 14
    ILLEGAL_USER_NAME              = 15
  end

  @[Flags]
  enum Trace
    TRANS     = (1 << 1)
    KEX       = (1 << 2)
    AUTH      = (1 << 3)
    CONN      = (1 << 4)
    SCP       = (1 << 5)
    SFTP      = (1 << 6)
    ERROR     = (1 << 7)
    PUBLICKEY = (1 << 8)
    SOCKET    = (1 << 9)
  end

  # HACK: the latest version of Mac OSX (kernel 14.3.0 and higher) uses macro _DARWIN_FEATURE_64_BIT_INODE
  # to modify the definition of `struct stat`. In particular, stat has one additional timestamp called
  # `st_btimespec` which contains file creation date and also increases the size of `ino_t` type from 32 to 64
  # bits. So we have to redefine LibC::Stat here, otherwise methods that use this struct populate its fields
  # incorrectly.
  # See https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man2/stat.2.html
  {% if flag?(:darwin) %}
    {% if flag?(:x86_64) %}
      struct Stat
        st_dev : Int32
        st_mode : LibC::ModeT
        st_nlink : UInt16
        st_ino : Int64
        st_uid : UInt32
        st_gid : UInt32
        st_rdev : Int32
        st_atimespec : LibC::Timespec
        st_mtimespec : LibC::Timespec
        st_ctimespec : LibC::Timespec
        st_btimespec : LibC::Timespec
        st_size : Int64
        st_blocks : Int64
        st_blksize : Int32
        st_flags : UInt32
        st_gen : UInt32
        st_lspare : Int32
        st_qspare1 : Int64
        st_qspare2 : Int64
      end
    {% else %}
      alias Stat = LibC::Stat
    {% end %}
  {% else %}
    alias Stat = LibC::Stat
  {% end %}

  ERROR_NONE                  =   0
  ERROR_AUTHENTICATION_FAILED = -18
  ERROR_SFTP_PROTOCOL         = -31
  ERROR_EAGAIN                = -37

  fun session_init = libssh2_session_init_ex(alloc : Void*, free : Void*, realloc : Void*, user_data : Void*) : Session
  fun session_free = libssh2_session_free(session : Session) : Int32
  fun trace = libssh2_trace(session : Session, bitmask : Trace)
  fun session_handshake = libssh2_session_handshake(session : Session, socket : Int32) : Int32
  fun session_banner_get = libssh2_session_banner_get(session : Session) : UInt8*
  fun session_banner_set = libssh2_session_banner_set(session : Session, banner : UInt8*) : Int32
  fun session_block_directions = libssh2_session_block_directions(session : Session) : BlockDirections
  fun session_callback_set = libssh2_session_callback_set(session : Session, cbtype : CallbackType, cb : Void*) : Void*
  fun session_disconnect = libssh2_session_disconnect_ex(session : Session, reason : DisconnectReason,
                                                         description : UInt8*, lang : UInt8*) : Int32
  fun session_flag = libssh2_session_flag(session : Session, flag : SessionFlag, value : Int32) : Int32
  fun session_get_blocking = libssh2_session_get_blocking(session : Session) : Int32
  fun session_get_timeout = libssh2_session_get_timeout(session : Session) : Int64
  fun session_hostkey = libssh2_session_hostkey(session : Session, len : LibC::SizeT*, type : Int32*) : UInt8*
  fun session_last_errno = libssh2_session_last_errno(session : Session) : Int32
  fun session_last_error = libssh2_session_last_error(session : Session, errmsg : UInt8**, errmsg_len : Int32*, want_buf : Int32) : Int32
  fun session_method_pref = libssh2_session_method_pref(session : Session, type : MethodType, prefs : UInt8*) : Int32
  fun session_methods = libssh2_session_methods(session : Session, type : MethodType) : UInt8*
  fun session_set_blocking = libssh2_session_set_blocking(session : Session, blocking : Int32)
  fun session_set_timeout = libssh2_session_set_timeout(session : Session, timeout : Int64)
  fun session_supported_algs = libssh2_session_supported_algs(session : Session, type : MethodType, algs : UInt8***) : Int32

  enum HashType
    MD5    = 1
    SHA1   = 2
    SHA256 = 3
    # SHA384 = 4
    # SHA512 = 5
  end

  fun hostkey_hash = libssh2_hostkey_hash(session : Session, type : HashType) : UInt8*

  fun userauth_authenticated = libssh2_userauth_authenticated(session : Session) : Int32
  fun userauth_hostbased_fromfile = libssh2_userauth_hostbased_fromfile_ex(session : Session, username : UInt8*, username_len : UInt32,
                                                                           pubkey : UInt8*, prvkey : UInt8*, passphrase : UInt8*,
                                                                           host : UInt8*, host_len : UInt32, localuser : UInt8*,
                                                                           localuser_len : UInt32) : Int32
  fun userauth_list = libssh2_userauth_list(session : Session, username : UInt8*, username_len : UInt32) : UInt8*

  alias PasswordChangeCallback = (Session, UInt8**, Int32*, Void**) -> Int32

  fun userauth_password = libssh2_userauth_password_ex(session : Session, username : UInt8*, username_len : UInt32,
                                                       password : UInt8*, password_len : UInt32, cb : PasswordChangeCallback) : Int32
  fun userauth_publickey_fromfile = libssh2_userauth_publickey_fromfile_ex(session : Session, username : UInt8*, username_len : UInt32,
                                                                           pubkey : UInt8*, privkey : UInt8*, passphrase : UInt8*) : Int32
  fun userauth_publickey_frommemory = libssh2_userauth_publickey_frommemory(session : Session, username : UInt8*, username_len : UInt32,
                                                                            pubkey : UInt8*, pubkey_len : LibC::SizeT,
                                                                            prvkey : UInt8*, prvkey_len : LibC::SizeT,
                                                                            passphrase : UInt8*) : Int32

  struct Password
    password : UInt8*
    length : UInt32
  end

  fun userauth_keyboard_interactive = libssh2_userauth_keyboard_interactive_ex(
    session : Session,
    username : UInt8*,
    username_len : UInt32,
    response : (UInt8*,  # name
Int32,                   # name_len
UInt8*,                  # instruction
Int32,                   # instruction_len
Int32,                   # num_prompts
Void*,                   # prompts
Password*,               # responses
Void*) -> Void
  ) : Int32

  fun keepalive_config = libssh2_keepalive_config(session : Session, want_reply : Int32, interval : UInt32)
  fun keepalive_send = libssh2_keepalive_send(session : Session, seconds_to_next : Int32*) : Int32

  alias KnownHosts = Void*

  # https://github.com/libssh2/libssh2/blob/6c7769dcc422250d14af1b06fce378b6ee009440/include/libssh2.h#L994
  @[Flags]
  enum TypeMask
    PLAIN  = 1
    SHA1   = 2
    CUSTOM = 3

    KEYENC_RAW    = (1 << 16)
    KEYENC_BASE64 = (2 << 16)

    KEY_RSA1   = (1 << 18)
    KEY_SSHRSA = (2 << 18)
    KEY_SSHDSS = (3 << 18)

    KEY_ECDSA_256 = (4 << 18)
    KEY_ECDSA_384 = (5 << 18)
    KEY_ECDSA_521 = (6 << 18)
    KEY_ED25519   = (7 << 18)

    KEY_UNKNOWN = (15 << 18)
  end

  enum KnownHostCheck
    MATCH    = 0
    MISMATCH = 1
    NOTFOUND = 2
    FAILURE  = 3
  end

  struct KnownHost
    magic : UInt32
    node : Void*
    name : UInt8*
    key : UInt8*
    typemask : TypeMask
  end

  KNOWNHOST_FILE_OPENSSH = 1

  fun knownhost_init = libssh2_knownhost_init(session : Session) : KnownHosts
  fun knownhost_free = libssh2_knownhost_free(kh : KnownHosts)
  fun knownhost_add = libssh2_knownhost_addc(kh : KnownHosts, host : UInt8*, salt : UInt8*, key : UInt8*, keylen : LibC::SizeT,
                                             comment : UInt8*, commentlen : LibC::SizeT, typemask : TypeMask,
                                             store : KnownHost**) : Int32
  fun knownhost_check = libssh2_knownhost_check(kh : KnownHosts, host : UInt8*, key : UInt8*, keylen : LibC::SizeT,
                                                typemask : TypeMask, store : KnownHost**) : KnownHostCheck
  fun knownhost_checkp = libssh2_knownhost_checkp(kh : KnownHosts, host : UInt8*, port : Int32, key : UInt8*, keylen : LibC::SizeT,
                                                  typemask : TypeMask, store : KnownHost**) : KnownHostCheck
  fun knownhost_get = libssh2_knownhost_get(kh : KnownHosts, store : KnownHost**, prev : KnownHost*) : Int32
  fun knownhost_del = libssh2_knownhost_del(kh : KnownHosts, entry : KnownHost*) : Int32
  fun knownhost_readfile = libssh2_knownhost_readfile(kh : KnownHosts, filename : UInt8*, type : Int32) : Int32
  fun knownhost_readline = libssh2_knownhost_readline(kh : KnownHosts, line : UInt8*, len : LibC::SizeT, type : Int32) : Int32
  fun knownhost_writefile = libssh2_knownhost_writefile(kh : KnownHosts, filename : UInt8*, type : Int32) : Int32
  fun knownhost_writeline = libssh2_knownhost_writeline(kh : KnownHosts, known : KnownHost*, buffer : UInt8*, buflen : LibC::SizeT,
                                                        outlen : LibC::SizeT*, type : Int32) : Int32

  alias Channel = Void*

  SSH_EXTENDED_DATA_STDERR    =  1
  CHANNEL_FLUSH_EXTENDED_DATA = -1
  CHANNEL_FLUSH_ALL           = -2

  CHANNEL_MINADJUST      = 1024
  CHANNEL_WINDOW_DEFAULT = (2*1024*1024)
  CHANNEL_PACKET_DEFAULT = 32_768

  TERM_WIDTH     = 80
  TERM_HEIGHT    = 24
  TERM_WIDTH_PX  =  0
  TERM_HEIGHT_PX =  0

  enum ExtendedData
    NORMAL = 0
    IGNORE = 1
    MERGE  = 2
  end

  fun channel_free = libssh2_channel_free(ch : Channel) : Int32
  fun channel_open = libssh2_channel_open_ex(session : Session, channel_type : UInt8*, channel_type_len : UInt32,
                                             window_size : UInt32, packet_size : UInt32, message : UInt8*,
                                             message_len : UInt32) : Channel
  fun channel_direct_tcpip = libssh2_channel_direct_tcpip_ex(session : Session, host : UInt8*, port : Int32,
                                                             shost : UInt8*, sport : Int32) : Channel
  fun channel_direct_streamlocal = libssh2_channel_direct_streamlocal_ex(session : Session, socket_path : UInt8*, shost : UInt8*, sport : Int32) : Channel
  fun channel_close = libssh2_channel_close(ch : Channel) : Int32
  fun channel_eof = libssh2_channel_eof(ch : Channel) : Int32
  fun channel_process_startup = libssh2_channel_process_startup(ch : Channel, request : UInt8*, request_len : UInt32,
                                                                message : UInt8*, message_len : UInt32) : Int32
  fun channel_flush = libssh2_channel_flush_ex(ch : Channel, stream_id : Int32) : Int32
  fun channel_get_exit_signal = libssh2_channel_get_exit_signal(ch : Channel, exitsignal : UInt8**, exitsignal_len : LibC::SizeT*,
                                                                errmsg : UInt8**, errmsg_len : LibC::SizeT*,
                                                                langtag : UInt8**, langtag_len : LibC::SizeT*) : Int32
  fun channel_get_exit_status = libssh2_channel_get_exit_status(ch : Channel) : Int32
  fun channel_handle_extended_data = libssh2_channel_handle_extended_data2(ch : Channel, extended_data : ExtendedData) : Int32
  fun channel_read = libssh2_channel_read_ex(ch : Channel, stream_id : Int32, buf : UInt8*, buflen : LibC::SizeT) : LibC::SSizeT
  fun channel_write = libssh2_channel_write_ex(ch : Channel, stream_id : Int32, buf : UInt8*, buflen : LibC::SizeT) : LibC::SSizeT
  fun channel_receive_window_adjust = libssh2_channel_receive_window_adjust2(ch : Channel, adj : UInt64, force : UInt8,
                                                                             window : UInt32*) : Int32
  fun channel_request_pty = libssh2_channel_request_pty_ex(ch : Channel, term : UInt8*, term_len : UInt32, modes : UInt8*, modes_len : UInt32,
                                                           width : Int32, height : Int32, width_px : Int32, height_px : Int32) : Int32
  fun channel_send_eof = libssh2_channel_send_eof(ch : Channel) : Int32
  fun channel_setenv = libssh2_channel_setenv_ex(ch : Channel, varname : UInt8*, varname_len : UInt32,
                                                 value : UInt8*, value_len : UInt32) : Int32
  fun channel_wait_closed = libssh2_channel_wait_closed(ch : Channel) : Int32
  fun channel_wait_eof = libssh2_channel_wait_eof(ch : Channel) : Int32
  fun channel_window_read = libssh2_channel_window_read_ex(ch : Channel, read_avail : UInt64*, window_size_initial : UInt64*) : UInt64
  fun channel_window_write = libssh2_channel_window_write_ex(ch : Channel, window_size_initial : UInt64*) : UInt64

  alias Listener = Void*

  fun channel_forward_listen = libssh2_channel_forward_listen_ex(session : Session, host : UInt8*, port : Int32, bound_port : Int32*,
                                                                 queue_maxsize : Int32) : Listener
  fun channel_forward_accept = libssh2_channel_forward_accept(listener : Listener) : Channel
  fun channel_forward_cancel = libssh2_channel_forward_cancel(listener : Listener) : Int32

  alias Agent = Void*

  struct AgentPublicKey
    magic : UInt32
    node : Void*
    blob : UInt8*
    blob_len : LibC::SizeT
    comment : UInt8*
  end

  fun agent_init = libssh2_agent_init(session : Session) : Agent
  fun agent_free = libssh2_agent_free(agent : Agent)
  fun agent_connect = libssh2_agent_connect(agent : Agent) : Int32
  fun agent_disconnect = libssh2_agent_disconnect(agent : Agent) : Int32
  fun agent_get_identity = libssh2_agent_get_identity(agent : Agent, store : AgentPublicKey**, prev : AgentPublicKey*) : Int32
  fun agent_list_identities = libssh2_agent_list_identities(agent : Agent) : Int32
  fun agent_userauth = libssh2_agent_userauth(agent : Agent, username : UInt8*, identity : AgentPublicKey*) : Int32

  fun scp_recv = libssh2_scp_recv(session : Session, path : UInt8*, stat : Stat*) : Channel
  fun scp_send = libssh2_scp_send64(session : Session, path : UInt8*, mode : Int32, size : UInt64,
                                    mtime : LibC::TimeT, atime : LibC::TimeT) : Channel

  alias SFTP = Void*

  struct SFTPAttrs
    flags : UInt64
    filesize : UInt64
    uid : UInt64
    gid : UInt64
    permissions : UInt64
    atime : UInt64
    mtime : UInt64
  end

  # File type
  SFTP_S_IFMT   = 0o0170000 # type of file mask
  SFTP_S_IFIFO  = 0o0010000 # named pipe (fifo)
  SFTP_S_IFCHR  = 0o0020000 # character special
  SFTP_S_IFDIR  = 0o0040000 # directory
  SFTP_S_IFBLK  = 0o0060000 # block special
  SFTP_S_IFREG  = 0o0100000 # regular
  SFTP_S_IFLNK  = 0o0120000 # symbolic link
  SFTP_S_IFSOCK = 0o0140000 # socket

  # File mode
  # Read, write, execute/search by owner
  SFTP_S_IRWXU = 0o0000700 # RWX mask for owner
  SFTP_S_IRUSR = 0o0000400 # R for owner
  SFTP_S_IWUSR = 0o0000200 # W for owner
  SFTP_S_IXUSR = 0o0000100 # X for owner

  # Read, write, execute/search by group
  SFTP_S_IRWXG = 0o0000070 # RWX mask for group
  SFTP_S_IRGRP = 0o0000040 # R for group
  SFTP_S_IWGRP = 0o0000020 # W for group
  SFTP_S_IXGRP = 0o0000010 # X for group

  # Read, write, execute/search by others
  SFTP_S_IRWXO = 0o0000007 # RWX mask for other
  SFTP_S_IROTH = 0o0000004 # R for other
  SFTP_S_IWOTH = 0o0000002 # W for other
  SFTP_S_IXOTH = 0o0000001 # X for other

  enum StatType
    STAT    = 0
    LSTAT   = 1
    SETSTAT = 2
  end

  @[Flags]
  enum FXF
    READ   = 0x00000001
    WRITE  = 0x00000002
    APPEND = 0x00000004
    CREAT  = 0x00000008
    TRUNC  = 0x00000010
    EXCL   = 0x00000020
  end

  SFTP_OPENFILE = 0
  SFTP_OPENDIR  = 1

  enum LinkType
    SYMLINK  = 0
    READLINK = 1
    REALPATH = 2
  end

  enum RenameFlags
    OVERWRITE = 0x00000001
    ATOMIC    = 0x00000002
    NATIVE    = 0x00000004
  end

  fun sftp_init = libssh2_sftp_init(session : Session) : SFTP
  fun sftp_shutdown = libssh2_sftp_shutdown(sftp : SFTP) : Int32
  fun sftp_close = libssh2_sftp_close_handle(sftp : SFTP) : Int32
  fun sftp_fstat = libssh2_sftp_fstat_ex(sftp : SFTP, attrs : SFTPAttrs*, setstat : Int32) : Int32
  fun sftp_fsync = libssh2_sftp_fsync(sftp : SFTP) : Int32
  fun sftp_get_channel = libssh2_sftp_get_channel(sftp : SFTP) : Channel
  fun sftp_last_error = libssh2_sftp_last_error(sftp : SFTP) : UInt64
  fun sftp_stat = libssh2_sftp_stat_ex(sftp : SFTP, path : UInt8*, path_len : UInt32, stat_type : StatType,
                                       attrs : SFTPAttrs*) : Int32
  fun sftp_mkdir = libssh2_sftp_mkdir_ex(sftp : SFTP, path : UInt8*, path_len : UInt32, mode : Int64) : Int32
  fun sftp_open = libssh2_sftp_open_ex(sftp : SFTP, filename : UInt8*, filename_len : UInt32, flags : FXF,
                                       mode : Int64, open_type : Int32) : SFTP
  fun sftp_read = libssh2_sftp_read(sftp : SFTP, buffer : UInt8*, buffer_maxlen : LibC::SizeT) : LibC::SSizeT
  fun sftp_readdir = libssh2_sftp_readdir_ex(sftp : SFTP, buffer : UInt8*, buf_len : LibC::SizeT,
                                             longentry : UInt8*, longentry_len : LibC::SizeT, attrs : SFTPAttrs*) : Int32
  fun sftp_symlink = libssh2_sftp_symlink_ex(sftp : SFTP, path : UInt8*, path_len : UInt32, target : UInt8*, target_len : UInt32,
                                             link_type : LinkType) : Int32
  fun sftp_rename = libssh2_sftp_rename_ex(sftp : SFTP, src : UInt8*, src_len : UInt32, dst : UInt8*, dst_len : UInt32,
                                           flags : RenameFlags) : Int32
  fun sftp_rmdir = libssh2_sftp_rmdir_ex(sftp : SFTP, path : UInt8*, path_len : UInt32) : Int32
  fun sftp_seek = libssh2_sftp_seek64(sftp : SFTP, offset : UInt64)
  fun sftp_tell = libssh2_sftp_tell64(sftp : SFTP) : UInt64
  fun sftp_unlink = libssh2_sftp_unlink_ex(sftp : SFTP, filename : UInt8*, filename_len : UInt32) : Int32
  fun sftp_write = libssh2_sftp_write(sftp : SFTP, buffer : UInt8*, count : LibC::SizeT) : LibC::SSizeT
end
