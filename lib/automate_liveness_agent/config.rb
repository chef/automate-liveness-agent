require "json"
require "logger"

module AutomateLivenessAgent
  class ConfigError < StandardError
  end

  class Config

    DEFAULT_CONFIG_PATH = "/etc/chef/config.json".freeze
    DEFAULT_VERIFY_MODE = "verify_peer".freeze

    STDOUT_STRING = "STDOUT".freeze
    STDERR_STRING = "STDERR".freeze

    SIZE_512K = 1024 * 512
    SIZE_2K   = 1024 * 2

    LOGGER_STRESS_MODE = "LOGGER_STRESS_MODE".freeze

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
    attr_reader :client_key
    attr_reader :client_name
    attr_reader :data_collector_url
    attr_reader :entity_uuid
    attr_reader :org_name
    attr_reader :ssl_verify_mode
    attr_reader :ssl_ca_file
    attr_reader :ssl_ca_path
    attr_reader :trusted_certs_dir
    attr_reader :unprivileged_uid
    attr_reader :unprivileged_gid
    attr_reader :install_check_file
    attr_reader :log_file

    def self.load(config_path)
      c = new(config_path)
      c.load
      c
    end

    def initialize(config_path)
      # Internal variables (doesn't map to config)
      @config_path  = File.expand_path(config_path || DEFAULT_CONFIG_PATH, Dir.pwd)
      @logger       = nil

      # Variables that map to config settings
      @chef_server_fqdn   = nil
      @client_key         = nil
      @client_key_path    = nil
      @client_name        = nil
      @data_collector_url = nil
      @entity_uuid        = nil
      @org_name           = nil
      @ssl_verify_mode    = DEFAULT_VERIFY_MODE
      @ssl_ca_file        = nil
      @ssl_ca_path        = nil
      @trusted_certs_dir  = nil
      @unprivileged_uid   = nil
      @unprivileged_gid   = nil
      @install_check_file = nil
      @log_file           = nil
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

    # The logger should only be setup after privileges are dropped. Otherwise
    # you can get into a situation where you've created the logfile as root,
    # but no longer have root privileges and are not allowed to rotate the logfile
    def setup_logger
      @logger ||= Logger.new(validate_and_normalize_log_path(log_file), 1, logfile_max_size)
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
        raise ConfigError, "Config file '#{config_path}' is missing mandatory setting(s): \"#{missing_settings.join('","')}\""
      end

      # Mandatory config
      @chef_server_fqdn   = config_data["chef_server_fqdn"]
      @client_key_path    = config_data["client_key_path"]
      @client_name        = config_data["client_name"]
      @data_collector_url = config_data["data_collector_url"]
      @entity_uuid        = config_data["entity_uuid"]
      @org_name           = config_data["org_name"]
      @unprivileged_uid   = config_data["unprivileged_uid"]
      @unprivileged_gid   = config_data["unprivileged_gid"]

      # Optional config
      if config_data.key?("ssl_verify_mode") && !!config_data["ssl_verify_mode"]
        sanity_check_ssl_verify_mode(config_data["ssl_verify_mode"])
      end

      if config_data.key?("ssl_ca_file") && !!config_data["ssl_ca_file"]
        sanity_check_ssl_ca_file(config_data["ssl_ca_file"])
      end

      if config_data.key?("ssl_ca_path") && !!config_data["ssl_ca_path"]
        sanity_check_ssl_ca_path(config_data["ssl_ca_path"])
      end

      if config_data.key?("trusted_certs_dir") && !!config_data["trusted_certs_dir"]
        sanity_check_trusted_certs_dir(config_data["trusted_certs_dir"])
      end

      @install_check_file = config_data["install_check_file"]
      @log_file           = config_data["log_file"]

      self
    end

    private

    def sanity_check_ssl_verify_mode(verify_mode)
      if verify_mode =~ /^verify_(peer|none)$/
        @ssl_verify_mode = verify_mode
      else
        raise(
          ConfigError,
          "'#{verify_mode}' is not a valid ssl_verify_mode."\
          " Valid options are 'verify_peer' and 'verify_none'."
        )
      end
    end

    def sanity_check_ssl_ca_path(ca_path)
      if File.directory?(ca_path)
        @ssl_ca_path = ca_path
      else
        raise ConfigError, "ssl_ca_path '#{ca_path}' is not a directory"
      end
    end

    def sanity_check_ssl_ca_file(ca_file)
      if File.exist?(ca_file)
        @ssl_ca_file = ca_file
      else
        raise ConfigError, "ssl_ca_file '#{ca_file}' does not exist"
      end
    end

    def sanity_check_trusted_certs_dir(dir)
      if File.directory?(dir)
        @trusted_certs_dir = dir
      else
        raise ConfigError, "trusted_certs_dir '#{dir}' is not a directory"
      end
    end

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

    def validate_and_normalize_log_path(log_path)
      case log_path
      when STDOUT_STRING, nil
        STDOUT
      when STDERR_STRING
        STDERR
      else
        validate_log_path(log_path)
        log_path
      end
    end

    def validate_log_path(log_path)
      log_dir = File.dirname(log_path)
      unless File.directory?(log_dir)
        raise ConfigError, "Log directory '#{log_dir}' (inferred from log_path config) does not exist or is not a directory"
      end
      unless File.writable?(log_dir)
        raise ConfigError, "Log directory '#{log_dir}' (inferred from log_path config) is not writable by current user (uid: #{Process.uid})"
      end
      if File.exist?(log_path) && !File.writable?(log_path)
        raise ConfigError, "Log file '#{log_file}' (set by log_path config) is not writable by current user (uid: #{Process.uid})"
      end
      log_path
    end

    def logfile_max_size
      if ENV[LOGGER_STRESS_MODE]
        SIZE_2K
      else
        SIZE_512K
      end

    end

  end
end
