require "json"

module AutomateLivenessAgent
  class ConfigError < StandardError
  end

  class Config

    DEFAULT_CONFIG_PATH = "/etc/chef/config.json".freeze

    MANDATORY_CONFIG_SETTINGS = %w{
      chef_server_fqdn
      client_key_path
      client_name
      data_collector_url
      entity_uuid
      org_name
      unprivileged_uid
      unprivileged_gid
    }.freeze

    attr_reader :config_path
    attr_reader :chef_server_fqdn
    attr_reader :client_key
    attr_reader :client_key_path
    attr_reader :client_name
    attr_reader :data_collector_url
    attr_reader :entity_uuid
    attr_reader :org_name
    attr_reader :unprivileged_uid
    attr_reader :unprivileged_gid

    def self.load(config_path)
      c = new(config_path)
      c.load
      c
    end

    def initialize(config_path)
      @config_path        = File.expand_path(config_path || DEFAULT_CONFIG_PATH, Dir.pwd)
      @chef_server_fqdn   = nil
      @client_key         = nil
      @client_key_path    = nil
      @client_name        = nil
      @data_collector_url = nil
      @entity_uuid        = nil
      @org_name           = nil
      @unprivileged_uid   = nil
      @unprivileged_gid   = nil
    end

    def load
      load_config_file
      load_client_key
    end

    def load_data(config_data)
      apply_config_values(config_data)
      load_client_key
      self
    end

    def load_config_file
      sanity_check_config_path
      config_data = parse_config_file
      apply_config_values(config_data)
    end

    def load_client_key
      if !(File.exist?(client_key_path) && File.readable?(client_key_path))
        raise ConfigError,
          "Configured client_key_path '#{client_key_path}' does not exist or is not readable (current uid: #{Process.uid})"
      end
      @client_key = File.read(client_key_path)
    end

    def apply_config_values(config_data)
      missing_settings = MANDATORY_CONFIG_SETTINGS - config_data.keys
      unless missing_settings.empty?
        raise ConfigError, "Config file '#{config_path}' is missing mandatory setting(s): '#{missing_settings.join("','")}'"
      end

      @chef_server_fqdn   = config_data["chef_server_fqdn"]
      @client_key_path    = config_data["client_key_path"]
      @client_name        = config_data["client_name"]
      @data_collector_url = config_data["data_collector_url"]
      @entity_uuid        = config_data["entity_uuid"]
      @org_name           = config_data["org_name"]
      @unprivileged_uid   = config_data["unprivileged_uid"]
      @unprivileged_gid   = config_data["unprivileged_gid"]

      self
    end

    private

    def parse_config_file
      JSON.parse(File.read(config_path))
    rescue JSON::ParserError
      # TODO: errors from the json gem/lib are bad, but we're trying to use as
      # much stdlib as we can here (so no ffi-yajl). Is there a lint tool we could make or recommend here?
      # Would be great to put a JSON checker bin in the ffi-yajl gem...
      raise ConfigError, "Config file '#{config_path}' has a JSON formatting error"
    end

    def sanity_check_config_path
      if !File.exist?(config_path)
        raise ConfigError, "Config file '#{config_path}' does not exist or is not readable"
      end
      if !File.readable?(config_path)
        raise ConfigError, "Config file '#{config_path}' is not readable (current uid = #{Process.euid})"
      end
      if File.size(config_path) == 0
        raise ConfigError, "Config file '#{config_path}' is empty"
      end
    end

  end
end
