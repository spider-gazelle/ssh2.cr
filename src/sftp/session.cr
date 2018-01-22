require "./base"

module SSH2::SFTP
  class Session
    include Base
    # Returns the underlying channel
    def channel
      handle = LibSSH2.sftp_get_channel(self)
      Channel.new @session, handle, false
    end

    # Performs lstat(2) operation on `path`
    def lstat(path)
      ret = LibSSH2.sftp_stat(self, path, path.bytesize.to_u32, LibSSH2::StatType::LSTAT, out attrs)
      check_error(ret)
      Attributes.new attrs
    end

    # Performs stat(2) operation on `path`
    def stat(path)
      ret = LibSSH2.sftp_stat(self, path, path.bytesize.to_u32, LibSSH2::StatType::STAT, out attrs)
      check_error(ret)
      Attributes.new attrs
    end

    # Sets attributes on `path`
    def setstat(path, attrs : Attributes)
      ret = LibSSH2.sftp_stat(self, path, path.bytesize.to_u32, LibSSH2::StatType::SETSTAT, attrs)
      check_error(ret)
    end

    # Create a directory on the remote file system.
    def mkdir(path, mode)
      ret = LibSSH2.sftp_mkdir(self, path, path.bytesize.to_u32, mode.to_i64)
      check_error(ret)
    end

    private def convert_to_fxf(mode)
      flags = LibSSH2::FXF::None
      if mode.includes?("r")
        flags |= LibSSH2::FXF::READ
      end
      if mode.includes?("w")
        flags |= LibSSH2::FXF::WRITE
      end
      if mode.includes?("+")
        flags |= LibSSH2::FXF::APPEND
      end
      if mode.includes?("c")
        flags |= LibSSH2::FXF::CREAT
      end
      if mode.includes?("!")
        flags |= LibSSH2::FXF::EXCL
      end
      flags
    end

    # Opens a remote `filename`.
    # Returns new SFTP instance.
    def open(filename, flags = "r", mode = 0)
      flags = convert_to_fxf(flags)
      handle = LibSSH2.sftp_open(self, filename, filename.bytesize.to_u32, flags, mode.to_i64, LibSSH2::SFTP_OPENFILE)
      unless handle
        check_sftp_error
      end
      File.new(self, handle)
    end

    # Opens a remote `dirname`.
    # Returns new SFTP instance.
    def open_dir(dirname, flags = "r", mode = 0)
      flags = convert_to_fxf(flags)
      handle = LibSSH2.sftp_open(self, dirname, dirname.bytesize.to_u32, flags, mode.to_i64, LibSSH2::SFTP_OPENDIR)
      unless handle
        check_sftp_error
      end
      Dir.new(self, handle)
    end

    # Create a new symlink
    def symlink(path, target)
      ret = LibSSH2.sftp_symlink(self, path, path.bytesize.to_u32, target, target_len.to_u32,
                                 LibSSH2::LinkType::SYMLINK)
      check_error(ret)
    end

    def readlink(path)
      buf_space = uninitialized UInt8[512]
      buf = buf_space.to_slice
      ret = LibSSH2.sftp_symlink(self, path, buf, buf.length.to_u32, LibSSH2::LinkType::READLINK)
      check_error(ret)
      String.new buf[0, ret]
    end

    def readlink(path)
      buf_space = uninitialized UInt8[512]
      buf = buf_space.to_slice
      ret = LibSSH2.sftp_symlink(self, path, buf, buf.length.to_u32, LibSSH2::LinkType::REALPATH)
      check_error(ret)
      String.new buf[0, ret]
    end

    def ulink(filename)
      ret = LibSSH2.sftp_unlink(self, filename, filename.bytesize.to_u32)
      check_error(ret)
    end

    # Rename a filesystem object on the remote filesystem.
    def rename(src, dst, flags : LibSSH2::RenameFlags = RenameFlags::OVERWRITE)
      ret = LibSSH2.sftp_rename(self, src, src.bytesize.to_u32, dst, dst.bytesize.to_u32, flags)
      check_error(ret)
    end

    def close
      return if @closed
      @closed = true
      LibSSH2.sftp_shutdown(@handle)
    end

    private def check_sftp_error
      SFTPError.check_error(LibSSH2.sftp_last_error(self))
    end
  end
end
