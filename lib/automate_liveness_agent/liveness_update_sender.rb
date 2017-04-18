require "automate_liveness_agent/api_client"

module AutomateLivenessAgent

  class LivenessUpdateSender

    attr_reader :config
    attr_reader :api_client

    DATA_TEMPLATE =<<-END_JSON_DATA
{
  "name": "data_bag_item_alatest_%s",
  "json_class": "Chef::DataBagItem",
  "chef_type": "data_bag_item",
  "data_bag": "alatest",
  "raw_data": {
    "id": "%s",
    "example": "example"
  }
}
END_JSON_DATA

    #UPDATE_INTERVAL_S = 60 * 30
    UPDATE_INTERVAL_S = 60

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
      loop do
        now = Time.now.to_i
        next_run = now + UPDATE_INTERVAL_S
        update
        GC.start
        ObjectSpace.count_objects(obj_counts)
        log("Total ruby objects: #{obj_counts[:TOTAL]}")
        sleep_time = [ next_run - Time.now.to_i, 0 ].max
        log("Waiting #{sleep_time}s until next update")
        sleep(sleep_time)
      end
    rescue Interrupt, SystemExit => e
      log("Signal received (#{e.inspect}), exiting")
      return true
    end

    def update
      api_client.request(update_data)
    end

    def update_data
      name = "example_" + Time.now.to_i.to_s
      sprintf(DATA_TEMPLATE, name, name)
    end

  end
end


