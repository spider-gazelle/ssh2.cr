{% skip_file unless flag?(:integration) %}
require "../spec_helper"

# Shared connection config + helper for the e2e suite. Only compiled under
# `-Dintegration`. Defaults match docker-compose.yml; override via ENV.
module Integration
  HOST = ENV["SPEC_SSH_HOST"]? || "localhost"
  PORT = (ENV["SPEC_SSH_PORT"]? || "10022").to_i
  USER = ENV["SPEC_SSH_USER"]? || "root"
  PASS = ENV["SPEC_SSH_PASS"]? || "somepassword"

  # Opens a session, logs in with the password and yields the authenticated
  # session, disconnecting on exit.
  def self.connect(&)
    SSH2::Session.open(HOST, PORT) do |session|
      session.login(USER, PASS)
      session.authenticated?.should be_true
      yield session
    end
  end
end
