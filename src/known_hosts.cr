class SSH2::KnownHosts
  include Enumerable(Pointer(LibSSH2::KnownHost))

  def initialize(@session)
    @handle = LibSSH2.knownhost_init(@session)
    raise SSH2Error.new "invalid handle" unless @handle
  end

  def add(host, salt, key, comment, typemask: LibSSH2::TypeMask)
    ret = LibSSH2.knownhost_add(self, host, salt, key, key.length, comment, comment.bytesize, typemask, out store)
    check_error(ret)
    store
  end

  def check(host, key, typemask: LibSSH2::TypeMask)
    ret = LibSSH2.knownhost_check(self, host, key, key.length, typemask, out store)
    check_error(ret)
    store
  end

  def checkp(host, port, key, typemask: LibSSH2::TypeMask)
    ret = LibSSH2.knownhost_checkp(self, host, port, key, key.length, typemask, out store)
    check_error(ret)
    store
  end

  def delete(entry: Pointer(LibSSH2::KnownHost))
    ret = LibSSH2.knownhost_del(self, entry)
    check_error(ret)
  end

  def read_file(filename)
    ret = LibSSH2.knownhost_readfile(self, filename, LibSSH2::KNOWNHOST_FILE_OPENSSH)
    check_error(ret)
  end

  def read_line(line)
    ret = LibSSH2.knownhost_readline(self, line, LibC::SizeT.cast(line.length), LibSSH2::KNOWNHOST_FILE_OPENSSH)
    check_error(ret)
  end

  def write_file(filename)
    ret = LibSSH2.knownhost_writefile(self, filename, LibSSH2::KNOWNHOST_FILE_OPENSSH)
    check_error(ret)
  end

  def each
    prev = Pointer(LibSSH2::KnownHost).null
    until LibSSH2.knownhost_get(self, out store, prev) == 1
      yield store
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
