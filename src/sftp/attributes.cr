# Wraps a remote file's SFTP attributes — size, owner, permissions and times —
# as returned by `File#fstat` and `Session#stat`/`#lstat`.
class SSH2::SFTP::Attributes
  # Marks which attribute fields are present.
  @[Flags]
  enum Flags : UInt64
    SIZE        = 0x00000001
    UIDGID      = 0x00000002
    PERMISSIONS = 0x00000004
    ACMODTIME   = 0x00000008
    EXTENDED    = 0x80000000
  end

  def initialize(@stat : LibSSH2::SFTPAttrs)
  end

  def initialize
    initialize(LibSSH2::SFTPAttrs.new)
  end

  # Which attribute fields are populated.
  def flags
    Flags.new(@stat.flags)
  end

  # :ditto:
  def flags=(v : Flags)
    @stat.flags = v.value
  end

  # File size in bytes.
  def size
    @stat.filesize
  end

  # Owner user id.
  def uid
    @stat.uid
  end

  # :ditto:
  def uid=(v)
    @stat.uid = v.to_u64
  end

  # Owner group id.
  def gid
    @stat.gid
  end

  # :ditto:
  def gid=(v)
    @stat.gid = v.to_u64
  end

  # POSIX permission bits.
  def permissions
    @stat.permissions
  end

  # :ditto:
  def permissions(v)
    @stat.permissions = v.to_u64
  end

  # Last access time.
  def atime
    Time.unix(@stat.atime.to_i64)
  end

  # :ditto:
  def atime=(v : Time)
    @stat.atime = v.to_unix
  end

  # Last modification time.
  def mtime
    Time.unix(@stat.mtime.to_i64)
  end

  # :ditto:
  def mtime=(v : Time)
    @stat.mtime = v.to_unix
  end

  def to_unsafe
    pointerof(@stat)
  end
end
