class SSH2::SFTP::Attributes
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

  def flags
    Flags.new(@stat.flags)
  end

  def flags=(v : Flags)
    @stat.flags = v.value
  end

  def size
    @stat.filesize
  end

  def uid
    @stat.uid
  end

  def uid=(v)
    @stat.uid = v.to_u64
  end

  def gid
    @stat.gid
  end

  def gid=(v)
    @stat.gid = v.to_u64
  end

  def permissions
    @stat.permissions
  end

  def permissions(v)
    @stat.permissions = v.to_u64
  end

  def atime
    Time.unix(@stat.atime.to_i32)
  end

  def atime=(v : Time)
    @stat.atime = v.to_utc.to_i.to_u64
  end

  def mtime
    Time.epoch(@stat.mtime.to_i32)
  end

  def mtime=(v : Time)
    @stat.mtime = v.to_utc.to_i.to_u64
  end

  def to_unsafe
    pointerof(@stat)
  end
end
