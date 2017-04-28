require "json"
require "sinatra"

class Pings
  def self.reset
    @@pings = 0
  end

  def self.increment
    @@pings += 1
  end

  def self.count
    @@pings
  end
end

Pings.reset

get "/reset-pings" do
  Pings.reset
  Pings.count
end

get "/pings" do
  Pings.count
end

post "/data-collector/v0" do
  body = request.body.read
  payload = JSON.load(body)

  # Since we're both using the chef-client to install the agent and piggy backing
  # off of it's configuration, our fake Automate data collector endpoint is going
  # is going to receive all sorts of data.  For our tests we only care if
  # the installed liveness agent is sending node_pings, therefore we'll only
  # increment the ping count for that message.
  Pings.increment if payload["message_type"] == "node_ping"

  status 201
end
