require "automate_liveness_agent/api_client"
require "time"

module AutomateLivenessAgent

  class LivenessUpdateSender

    attr_reader :config
    attr_reader :api_client

    UPDATE_INTERVAL_S = 60 * 30

    def initialize(config)
      @config = config

      @api_client = APIClient.new(config)
      api_client.load_and_verify_config
    end

    def log(message)
      print("#{message}\n")
    end

    def main_loop
      obj_counts = {}
      log("PROCESS ID: #{Process.pid}")

      interval = (ENV["INTERVAL"] || UPDATE_INTERVAL_S).to_i
      loop do
        if chef_uninstalled?
          log("Chef Client appears to have been uninstalled, shutting down")
          break false
        end
        now = Time.now.to_i
        next_run = now + interval
        update
        GC.start
        ObjectSpace.count_objects(obj_counts)
        log("Total ruby objects: #{obj_counts[:TOTAL]}; Free heap slots: #{obj_counts[:FREE]}")
        sleep_time = [ next_run - Time.now.to_i, 0 ].max
        log("Waiting #{sleep_time}s until next update")
        sleep(sleep_time)
      end
    rescue Interrupt, SystemExit => e
      log("Signal received (#{e.inspect}), exiting")
      return true
    end

    def update
      api_client.request(update_payload)
    end

    def base_payload
      @base_payload ||= {
        "chef_server_fqdn" => config.chef_server_fqdn,
        "source" => "liveness_agent",
        "message_version" => "0.0.1",
        "event_type" => "node_ping",
        "organization_name" => config.org_name,
        "node_name" => config.client_name,
        "entity_uuid" => config.entity_uuid,
      }.freeze
    end

    def update_payload
      base_payload.merge("@timestamp" => Time.now.utc.iso8601).to_json
    end

    def chef_uninstalled?
      return false if config.install_check_file.nil?
      !File.exist?(config.install_check_file)
    end
  end
end
