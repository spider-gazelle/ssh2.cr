require "./lib_ssh2"

module SSH2
  class SSH2Error < Exception; end

  enum TerminalMode
    # Interrupt character; 255 if none. Similarly for the other characters.
    # Not all of these characters are supported on all systems.
    VINTR = 1

    # The quit character (sends SIGQUIT signal on POSIX systems).
    VQUIT = 2

    # Erase the character to left of the cursor.
    VERASE = 3

    # Kill the current input line.
    VKILL = 4

    # End-of-file character (sends EOF from the terminal).
    VEOF = 5

    # End-of-line character in addition to carriage return and/or linefeed.
    VEOL = 6

    # Additional end-of-line character.
    VEOL2 = 7

    # Continues paused output (normally control-Q).
    VSTART = 8

    # Pauses output (normally control-S).
    VSTOP = 9

    # Suspends the current program.
    VSUSP = 10

    # Another suspend character.
    VDSUSP = 11

    # Reprints the current input line.
    VREPRINT = 12

    # Erases a word left of cursor.
    VWERASE = 13

    # Enter the next character typed literally, even if it is a special
    # character.
    VLNEXT = 14

    # Character to flush output.
    VFLUSH = 15

    # Switch to a different shell layer.
    VSWITCH = 16

    # Prints system status line (load, command, pid, etc).
    VSTATUS = 17

    # Toggles the flushing of terminal output.
    VDISCARD = 18

    # The ignore parity flag. The parameter SHOULD be 0 if this flag is FALSE,
    # and 1 if it is TRUE.
    IGNPAR = 30

    # Mark parity and framing errors.
    PARMRK = 31

    # Enable checking of parity errors.
    INPCK = 32

    # Strip 8th bit off characters.
    ISTRIP = 33

    # Map NL into CR on input.
    INCLR = 34

    # Ignore CR on input.
    IGNCR = 35

    # Map CR to NL on input.
    ICRNL = 36

    # Translate uppercase characters to lowercase.
    IUCLC = 37

    # Enable output flow control.
    IXON = 38

    # Any char will restart after stop.
    IXANY = 39

    # Enable input flow control.
    IXOFF = 40

    # Ring bell on input queue full.
    IMAXBEL = 41

    # Enable signals INTR, QUIT, [D]SUSP.
    ISIG = 50

    # Canonicalize input lines.
    ICANON = 51

    # Enable input and output of uppercase characters by preceding their
    # lowercase equivalents with "\".
    XCASE = 52

    # Enable echoing.
    ECHO = 53

    # Visually erase chars.
    ECHOE = 54

    # Kill character discards current line.
    ECHOK = 55

    # Echo NL even if ECHO is off.
    ECHONL = 56

    # Don't flush after interrupt.
    NOFLSH = 57

    # Stop background jobs from output.
    TOSTOP = 58

    # Enable extensions.
    IEXTEN = 59

    # Echo control characters as ^(Char).
    ECHOCTL = 60

    # Visual erase for line kill.
    ECHOKE = 61

    # Retype pending input.
    PENDIN = 62

    # Enable output processing.
    OPOST = 70

    # Convert lowercase to uppercase.
    OLCUC = 71

    # Map NL to CR-NL.
    ONLCR = 72

    # Translate carriage return to newline (output).
    OCRNL = 73

    # Translate newline to carriage return-newline (output).
    ONOCR = 74

    # Newline performs a carriage return (output).
    ONLRET = 75

    # 7 bit mode.
    CS7 = 90

    # 8 bit mode.
    CS8 = 91

    # Parity enable.
    PARENB = 92

    # Odd parity, else even.
    PARODD = 93

    # Specifies the input baud rate in bits per second.
    TTY_OP_ISPEED = 128

    # Specifies the output baud rate in bits per second.
    TTY_OP_OSPEED = 129
  end

  class SessionError < SSH2Error
    def initialize(session)
      @code = LibSSH2.session_last_errno(session)
      LibSSH2.session_last_error(session, out errmsg, out errmsg_len, 0)
      @msg = String.new errmsg, errmsg_len
      super("ERR #{@code}: #{@msg}")
    end

    def self.check_error(session, code)
      if code >= LibSSH2::ERROR_NONE || code == LibSSH2::ERROR_EAGAIN
        code
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

    def initialize(@code : UInt64, @reason : String)
      super("SFTP Error: #{@code} / #{@reason}")
    end

    def self.check_error(code)
      case code
      when 0
        # Do nothing, success
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
      else
        raise SFTPError.new(code, "unknown error #{code}")
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
