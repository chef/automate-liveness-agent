require "json"
require "sinatra"

set :environment, :production
set :bind, "0.0.0.0"

class Pings
  def self.reset(org)
    _pings[org] = 0
  end

  def self.increment(org)
    _pings[org] += 1
  end

  def self.count(org)
    _pings[org]
  end

  def self.reset_all
    @@pings = nil
  end

  def self._pings
    @@pings ||= Hash.new { |h, k| h[k] = 0 }
    @@pings
  end
end

get "/organizations/:org/reset-pings" do |org|
  Pings.reset(org)
  Pings.count(org).to_s
end

get "/organizations/:org/pings" do |org|
  request.logger.info "Pings count #{Pings.count(org)}"
  Pings.count(org).to_s
end

post "/organizations/:org/data-collector" do |org|
  body = request.body.read
  payload = JSON.parse(body)

  # Since we're both using the chef-client to install the agent and piggy backing
  # off of it's configuration, our fake Automate data collector endpoint is going
  # is going to receive all sorts of data.  For our tests we only care if
  # the installed liveness agent is sending node_pings, therefore we'll only
  # increment the ping count for that message.
  Pings.increment(org) if payload.key?("event_type") && payload["event_type"] == "node_ping"

  status 201
end
