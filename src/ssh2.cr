require "./lib_ssh2"

module SSH2
  class SSH2Error < Exception; end

  class SessionError < SSH2Error
    def initialize(session)
      @code = LibSSH2.session_last_errno(session)
      LibSSH2.session_last_error(session, out errmsg, out errmsg_len, 0)
      @msg = String.new errmsg, errmsg_len
      super("ERR #{@code}: #{@msg}")
    end

    def self.check_error(session, code)
      if code >= LibSSH2::ERROR_NONE || code == LibSSH2::ERROR_EAGAIN
        return code
      else
        raise SessionError.new(session)
      end
    end
  end

  class SFTPClosed < SSH2Error; end

  class SFTPError < SSH2Error
    class EOF < SFTPError; end
    class NoSuchFile < SFTPError; end
    class PermissionDenied < SFTPError; end
    class Failure < SFTPError; end
    class BadMessage < SFTPError; end
    class NoConnection < SFTPError; end
    class ConnectionLost < SFTPError; end
    class Unsupported < SFTPError; end
    class InvalidHandle < SFTPError; end
    class NoSuchFile < SFTPError; end
    class FileAlreadyExists < SFTPError; end
    class WriteProtect < SFTPError; end
    class NoMedia < SFTPError; end
    class NoSpaceOnFs < SFTPError; end
    class QuotaExceeded < SFTPError; end
    class UnknownPrincipal < SFTPError; end
    class LockConflict < SFTPError; end
    class DirNotEmpty < SFTPError; end
    class NotADirectory < SFTPError; end
    class InvalidFilename < SFTPError; end
    class LinkLoop < SFTPError; end

    def initialize(@code, @reason)
      super("SFTP Error: #{@code} / #{@reason}")
    end

    def self.check_error(code)
      case code
      when 1
        raise EOF.new(code, "EOF")
      when 2
        raise NoSuchFile.new(code, "No such file")
      when 3
        raise PermissionDenied.new(code, "Permission denied")
      when 4
        raise Failure.new(code, "Failure")
      when 5
        raise BadMessage.new(code, "Bad message")
      when 6
        raise NoConnection.new(code, "No connection")
      when 7
        raise ConnectionLost.new(code, "Connection lost")
      when 8
        raise Unsupported.new(code, "Unsupported")
      when 9
        raise InvalidHandle.new(code, "Invalid handle")
      when 10
        raise NoSuchFile.new(code, "No such file")
      when 11
        raise FileAlreadyExists.new(code, "File already exists")
      when 12
        raise WriteProtect.new(code, "Write protect")
      when 13
        raise NoMedia.new(code, "No media")
      when 14
        raise NoSpaceOnFs.new(code, "No space on filesystem")
      when 15
        raise QuotaExceeded.new(code, "Quota exceeded")
      when 16
        raise UnknownPrincipal.new(code, "Unknown principal")
      when 17
        raise LockConflict.new(code, "Lock conflict")
      when 18
        raise DirNotEmpty.new(code, "Dir not empty")
      when 19
        raise NotADirectory.new(code, "Not a directory")
      when 20
        raise InvalidFilename.new(code, "Invalid filename")
      when 21
        raise LinkLoop.new(code, "Link loop")
      end
    end
  end

  unless (rc = LibSSH2.init(0)) == 0
    raise SSH2Error.new "failed to initialize libssh2 (#{rc})"
  end

  def self.version
    String.new LibSSH2.version(0)
  end
end

require "./session"
require "./channel"
require "./listener"
require "./agent"
require "./known_hosts"
require "./sftp/*"
