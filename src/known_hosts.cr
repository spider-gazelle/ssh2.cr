require "./lib_ssh2"
require "./session"

class SSH2::KnownHosts
  struct Host
    getter name : String?
    getter key : String?
    getter typemask : LibSSH2::TypeMask?

    def initialize(@name, @key, @typemask)
    end
  end

  include Enumerable(Host)

  def initialize(@session : Session)
    @handle = LibSSH2.knownhost_init(@session)
    raise SSH2Error.new "invalid handle" unless @handle
  end

  def add(host, salt, key, comment, typemask : LibSSH2::TypeMask)
    ret = LibSSH2.knownhost_add(self, host, salt, key, key.size.to_u64,
                                comment, comment.bytesize.to_u64, typemask, out store)
    check_error(ret)
    store
  end

  def check(host, port, key, typemask : LibSSH2::TypeMask)
    LibSSH2.knownhost_checkp(self, host, port, key, key.size.to_u64, typemask, out store)
  end

  def delete_if
    each_unsafe do |known_host|
      if yield conv_to_host(known_host)
        ret = LibSSH2.knownhost_del(self, known_host)
        check_error(ret)
      end
    end
  end

  def read_file(filename)
    ret = LibSSH2.knownhost_readfile(self, filename, LibSSH2::KNOWNHOST_FILE_OPENSSH)
    check_error(ret)
  end

  def read_line(line)
    ret = LibSSH2.knownhost_readline(self, line, LibC::SizeT.new(line.size), LibSSH2::KNOWNHOST_FILE_OPENSSH)
    check_error(ret)
  end

  def write_file(filename)
    ret = LibSSH2.knownhost_writefile(self, filename, LibSSH2::KNOWNHOST_FILE_OPENSSH)
    check_error(ret)
  end

  def each
    each_unsafe do |known_host|
      yield conv_to_host(known_host)
    end
  end

  private def conv_to_host(known_host)
    name = String.new known_host.value.name if known_host.value.name
    key = String.new known_host.value.key if known_host.value.key
    Host.new(name, key, known_host.value.typemask)
  end

  private def each_unsafe
    prev = Pointer(LibSSH2::KnownHost).null
    until LibSSH2.knownhost_get(self, out store, prev) == 1
      yield store
      prev = store
    end
  end

  def finalize
    LibSSH2.knownhost_free(@handle)
  end

  def to_unsafe
    @handle
  end

  private def check_error(code)
    SessionError.check_error(@session, code)
  end
end
