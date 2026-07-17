require "./lib_ssh2"
require "./session"

# Manages a session's collection of known hosts, mirroring an OpenSSH
# `known_hosts` file: add and check host keys, and read/write the file.
class SSH2::KnownHosts
  # A single known-host entry: its `name`, `key` and `typemask`.
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

  # Add `host` with its `key` and `typemask` to the collection. `salt` is used
  # for hashed hostnames (empty for a plain name). Returns the stored entry.
  def add(host, salt, key, comment, typemask : LibSSH2::TypeMask)
    ret = LibSSH2.knownhost_add(self, host, salt, key, key.size.to_u64,
      comment, comment.bytesize.to_u64, typemask, out store)
    check_error(ret)
    store
  end

  # Check `host`/`port` and `key` against the collection. Returns a
  # `LibSSH2::KnownHostCheck` (`MATCH`, `MISMATCH`, `NOTFOUND` or `FAILURE`).
  def check(host, port, key, typemask : LibSSH2::TypeMask)
    LibSSH2.knownhost_checkp(self, host, port, key, key.size.to_u64, typemask, out store)
  end

  # Delete every known host for which the block returns a truthy value.
  def delete_if(&)
    each_unsafe do |known_host|
      if yield conv_to_host(known_host)
        ret = LibSSH2.knownhost_del(self, known_host)
        check_error(ret)
      end
    end
  end

  # Populate the collection from an OpenSSH `known_hosts` file at `filename`.
  def read_file(filename)
    ret = LibSSH2.knownhost_readfile(self, filename, LibSSH2::KNOWNHOST_FILE_OPENSSH)
    check_error(ret)
  end

  # Add a single host from one OpenSSH `known_hosts` line.
  def read_line(line)
    ret = LibSSH2.knownhost_readline(self, line, LibC::SizeT.new(line.size), LibSSH2::KNOWNHOST_FILE_OPENSSH)
    check_error(ret)
  end

  # Write the collection to an OpenSSH `known_hosts` file at `filename`.
  def write_file(filename)
    ret = LibSSH2.knownhost_writefile(self, filename, LibSSH2::KNOWNHOST_FILE_OPENSSH)
    check_error(ret)
  end

  # Yield each known host as a `Host`.
  def each(&)
    each_unsafe do |known_host|
      yield conv_to_host(known_host)
    end
  end

  private def conv_to_host(known_host)
    name = String.new known_host.value.name if known_host.value.name
    key = String.new known_host.value.key if known_host.value.key
    Host.new(name, key, known_host.value.typemask)
  end

  private def each_unsafe(&)
    prev = Pointer(LibSSH2::KnownHost).null
    loop do
      rc = LibSSH2.knownhost_get(self, out store, prev)
      # 1 means no more hosts; a negative rc raises instead of looping forever
      break if rc == 1
      check_error(rc)
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
