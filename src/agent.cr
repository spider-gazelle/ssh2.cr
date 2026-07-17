# Talks to the local ssh-agent (via `SSH_AUTH_SOCK`) to authenticate a session
# with one of the identities it holds. See `Session#login_with_agent`.
class SSH2::Agent
  # A public key held by the agent: its raw `public_key` blob and its `comment`.
  struct PublicKey
    getter public_key : Bytes
    getter comment : String

    def initialize(@public_key, @comment)
    end
  end

  include Enumerable(PublicKey)

  def initialize(@session : SSH2::Session)
    @handle = LibSSH2.agent_init(session)
    raise SSH2Error.new "invalid handle" unless @handle
  end

  # Connect to an ssh-agent running on the system.
  def connect
    ret = LibSSH2.agent_connect(self)
    check_error(ret)
  end

  # Close a connection to an ssh-agent.
  def disconnect
    ret = LibSSH2.agent_disconnect(self)
    check_error(ret)
  end

  # Request an ssh-agent to list of public keys, and stores them in the
  # internal collection of the handle.
  def list_identities
    ret = LibSSH2.agent_list_identities(self)
    check_error(ret)
  end

  # Authenticate username with agent
  def authenticate(username)
    ret : Int32? = nil
    each_unsafe do |key|
      @session.perform_nonblock do
        ret = LibSSH2.agent_userauth(self, username, key)
        case ret
        when 0
          return true
        when LibSSH2::ERROR_AUTHENTICATION_FAILED
          0
        else
          ret
        end
      end
    end
    raise SSH2Error.new "Failed to authenticate username #{username} with SSH agent"
  end

  # Yield each identity held by the agent as a `PublicKey`. Call
  # `list_identities` first to populate the collection.
  def each(&)
    each_unsafe do |key|
      yield PublicKey.new(
        Slice.new(key.value.blob, key.value.blob_len),
        String.new(key.value.comment))
    end
  end

  private def each_unsafe(&)
    prev = Pointer(LibSSH2::AgentPublicKey).null
    loop do
      rc = LibSSH2.agent_get_identity(self, out store, prev)
      # 1 means no more identities; a negative rc raises instead of looping forever
      break if rc == 1
      check_error(rc)
      yield store
      prev = store
    end
  end

  def finalize
    LibSSH2.agent_free(self)
  end

  def to_unsafe
    @handle
  end

  private def check_error(code)
    SessionError.check_error(@session, code)
  end
end
