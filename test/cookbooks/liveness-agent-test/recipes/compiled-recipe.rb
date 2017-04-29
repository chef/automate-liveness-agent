#  Copyright 2017 Chef Software, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

liveness_agent = <<'AUTOMATE_LIVENESS_AGENT'
#!/usr/bin/env ruby
## lib/automate_liveness_agent/vendor/mixlib-authentication/lib/mixlib/authentication/null_logger.rb ##
module Mixlib
  module Authentication
    module NullLogger
      attr_accessor :level
      %i{debug info warn error fatal}.each do |method_name|
        class_eval(<<-METHOD_DEFN, __FILE__, __LINE__)
          def #{method_name}(msg=nil, &block)
            true
          end
        METHOD_DEFN
      end
      %i{debug? info? warn? error? fatal?}.each do |method_name|
        class_eval(<<-METHOD_DEFN, __FILE__, __LINE__)
          def #{method_name}
            false
          end
        METHOD_DEFN
      end
    end
  end
end
## lib/automate_liveness_agent/vendor/mixlib-authentication/lib/mixlib/authentication.rb ##
module Mixlib
  module Authentication
    DEFAULT_SERVER_API_VERSION = "0"
    attr_accessor :logger
    module_function :logger, :logger=
    class AuthenticationError < StandardError
    end
    class MissingAuthenticationHeader < AuthenticationError
    end
    class Log
    end
    Mixlib::Authentication::Log.extend(Mixlib::Authentication::NullLogger)
    Mixlib::Authentication.logger = Mixlib::Authentication::Log
    Mixlib::Authentication.logger.level = :error
  end
end
## lib/automate_liveness_agent/vendor/mixlib-authentication/lib/mixlib/authentication/digester.rb ##
require "openssl"
module Mixlib
  module Authentication
    class Digester
      class << self
        def hash_file(f, digest = OpenSSL::Digest::SHA1)
          digester = digest.new
          buf = ""
          digester.update buf while f.read(16384, buf)
          ::Base64.encode64(digester.digest).chomp
        end
        def hash_string(str, digest = OpenSSL::Digest::SHA1)
          ::Base64.encode64(digest.digest(str)).chomp
        end
      end
    end
  end
end
## lib/automate_liveness_agent/vendor/mixlib-authentication/lib/mixlib/authentication/signedheaderauth.rb ##
require "time"
require "base64"
require "openssl/digest"
module Mixlib
  module Authentication
    module SignedHeaderAuth
      NULL_ARG = Object.new
      ALGORITHM_FOR_VERSION = {
        "1.0" => "sha1",
        "1.1" => "sha1",
        "1.3" => "sha256",
      }.freeze()
      SUPPORTED_ALGORITHMS = ["sha1"].freeze
      SUPPORTED_VERSIONS = ["1.0", "1.1"].freeze
      DEFAULT_SIGN_ALGORITHM = "sha1".freeze
      DEFAULT_PROTO_VERSION = "1.0".freeze
      def self.signing_object(args = {})
        SigningObject.new(args[:http_method],
                          args[:path],
                          args[:body],
                          args[:host],
                          args[:timestamp],
                          args[:user_id],
                          args[:file],
                          args[:proto_version],
                          args[:headers]
                         )
      end
      def algorithm
        ALGORITHM_FOR_VERSION[proto_version] || DEFAULT_SIGN_ALGORITHM
      end
      def proto_version
        DEFAULT_PROTO_VERSION
      end
      def sign(private_key, sign_algorithm = algorithm, sign_version = proto_version)
        digest = validate_sign_version_digest!(sign_algorithm, sign_version)
        header_hash = {
          "X-Ops-Sign" => "algorithm=#{sign_algorithm};version=#{sign_version};",
          "X-Ops-Userid" => user_id,
          "X-Ops-Timestamp" => canonical_time,
          "X-Ops-Content-Hash" => hashed_body(digest),
        }
        signature = Base64.encode64(do_sign(private_key, digest, sign_algorithm, sign_version)).chomp
        signature_lines = signature.split(/\n/)
        signature_lines.each_index do |idx|
          key = "X-Ops-Authorization-#{idx + 1}"
          header_hash[key] = signature_lines[idx]
        end
        Mixlib::Authentication.logger.debug "Header hash: #{header_hash.inspect}"
        header_hash
      end
      def validate_sign_version_digest!(sign_algorithm, sign_version)
        if ALGORITHM_FOR_VERSION[sign_version].nil?
          raise AuthenticationError,
            "Unsupported version '#{sign_version}'"
        end
        if ALGORITHM_FOR_VERSION[sign_version] != sign_algorithm
          raise AuthenticationError,
            "Unsupported algorithm #{sign_algorithm} for version '#{sign_version}'"
        end
        case sign_algorithm
        when "sha1"
          OpenSSL::Digest::SHA1
        when "sha256"
          OpenSSL::Digest::SHA256
        else
          raise "Unknown algorithm #{sign_algorithm}"
        end
      end
      def canonical_time
        Time.parse(timestamp).utc.iso8601
      end
      def canonical_path
        p = path.gsub(/\/+/, "/")
        p.length > 1 ? p.chomp("/") : p
      end
      def hashed_body(digest = OpenSSL::Digest::SHA1)
        @hashed_body_digest = nil unless defined?(@hashed_body_digest)
        if !@hashed_body_digest.nil? && @hashed_body_digest != digest
          raise "hashed_body must always be called with the same digest"
        else
          @hashed_body_digest = digest
        end
        @hashed_body ||= if self.file && self.file.respond_to?(:read)
                           digester.hash_file(self.file, digest)
                         else
                           digester.hash_string(self.body, digest)
                         end
      end
      def canonicalize_request(sign_algorithm = algorithm, sign_version = proto_version)
        digest = validate_sign_version_digest!(sign_algorithm, sign_version)
        canonical_x_ops_user_id = canonicalize_user_id(user_id, sign_version, digest)
        case sign_version
        when "1.3"
          [
            "Method:#{http_method.to_s.upcase}",
            "Path:#{canonical_path}",
            "X-Ops-Content-Hash:#{hashed_body(digest)}",
            "X-Ops-Sign:version=#{sign_version}",
            "X-Ops-Timestamp:#{canonical_time}",
            "X-Ops-UserId:#{canonical_x_ops_user_id}",
            "X-Ops-Server-API-Version:#{server_api_version}",
          ].join("\n")
        else
          [
            "Method:#{http_method.to_s.upcase}",
            "Hashed Path:#{digester.hash_string(canonical_path, digest)}",
            "X-Ops-Content-Hash:#{hashed_body(digest)}",
            "X-Ops-Timestamp:#{canonical_time}",
            "X-Ops-UserId:#{canonical_x_ops_user_id}",
          ].join("\n")
        end
      end
      def canonicalize_user_id(user_id, proto_version, digest = OpenSSL::Digest::SHA1)
        case proto_version
        when "1.1"
          digester.hash_string(user_id, digest)
        else
          user_id
        end
      end
      def parse_signing_description
        parts = signing_description.strip.split(";").inject({}) do |memo, part|
          field_name, field_value = part.split("=")
          memo[field_name.to_sym] = field_value.strip
          memo
        end
        Mixlib::Authentication.logger.debug "Parsed signing description: #{parts.inspect}"
        parts
      end
      def digester
        Mixlib::Authentication::Digester
      end
      def do_sign(private_key, digest, sign_algorithm, sign_version)
        string_to_sign = canonicalize_request(sign_algorithm, sign_version)
        Mixlib::Authentication.logger.debug "String to sign: '#{string_to_sign}'"
        case sign_version
        when "1.3"
          private_key.sign(digest.new, string_to_sign)
        else
          private_key.private_encrypt(string_to_sign)
        end
      end
      private :canonical_time, :canonical_path, :parse_signing_description, :digester, :canonicalize_user_id
    end
    SigningObject = Struct.new(:http_method, :path, :body, :host,
                                     :timestamp, :user_id, :file, :proto_version,
                                     :headers) do
      include SignedHeaderAuth
      def proto_version
        (self[:proto_version] || SignedHeaderAuth::DEFAULT_PROTO_VERSION).to_s
      end
      def server_api_version
        key = (self[:headers] || {}).keys.select do |k|
          k.casecmp("x-ops-server-api-version") == 0
        end.first
        if key
          self[:headers][key]
        else
          DEFAULT_SERVER_API_VERSION
        end
      end
    end
  end
end
## lib/automate_liveness_agent/version.rb ##
module AutomateLivenessAgent
  VERSION = "0.1.0"
end
## lib/automate_liveness_agent/config.rb ##
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
      @config_path  = File.expand_path(config_path || DEFAULT_CONFIG_PATH, Dir.pwd)
      @logger       = nil
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
      @chef_server_fqdn   = config_data["chef_server_fqdn"]
      @client_key_path    = config_data["client_key_path"]
      @client_name        = config_data["client_name"]
      @data_collector_url = config_data["data_collector_url"]
      @entity_uuid        = config_data["entity_uuid"]
      @org_name           = config_data["org_name"]
      @unprivileged_uid   = config_data["unprivileged_uid"]
      @unprivileged_gid   = config_data["unprivileged_gid"]
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
## lib/automate_liveness_agent/api_client.rb ##
require "openssl"
require "net/http"
require "uri"
module AutomateLivenessAgent
  class APIClient
    MIXLIB_AUTHN_PROTO_VERSION = "1.3".freeze
    APPLICATION_JSON = "application/json".freeze
    HTTP_METHOD = "POST".freeze
    VALID_PROTOCOLS = %w{ http https }.freeze
    BASE_HEADERS = {
      "Accept" => APPLICATION_JSON,
      "X-Chef-Version" => "13.0.0".freeze,
      "User-Agent" => "Automate Liveness Agent #{AutomateLivenessAgent::VERSION}".freeze,
      "Content-Type" => APPLICATION_JSON,
    }.freeze
    DEBUG = "DEBUG".freeze
    RETRY_LIMIT = 5
    ERROR = "Error".freeze
    SUCCESS = "Success".freeze
    HTTPS_SCHEME = "https".freeze
    attr_reader :config
    attr_reader :logger
    attr_reader :uri
    attr_reader :base_request_params
    attr_reader :private_key
    attr_reader :http
    def initialize(config, logger)
      @config = config
      @logger = logger
    end
    def load_and_verify_config
      parse_key
      parse_uri
      set_base_request_params
      setup_http_client
      self
    end
    def request(body)
      retry_count ||= -1
      retry_count += 1
      request_without_retries(body)
    rescue Net::HTTPError, Net::HTTPRetriableError, Net::HTTPServerException, Net::HTTPFatalError => e
      error_response = e.response
      log_response(ERROR, error_response)
      retry if wait_for_retry_or_give_up(retry_count)
    rescue SocketError, Errno::ETIMEDOUT, Errno::ECONNRESET => e
      log("Error initiating connection to #{uri.host}:#{uri.port} - #{e}")
      retry if wait_for_retry_or_give_up(retry_count)
    rescue Errno::ECONNREFUSED => e
      log("Connection refused for #{uri.host}:#{uri.port} - #{e}")
      retry if wait_for_retry_or_give_up(retry_count)
    rescue Timeout::Error => e
      log("Timeout connecting to #{uri.host}:#{uri.port} - #{e}")
      retry if wait_for_retry_or_give_up(retry_count)
    rescue OpenSSL::SSL::SSLError => e
      log("SSL error connecting to #{uri.host}:#{uri.port} - #{e}")
      retry if wait_for_retry_or_give_up(retry_count)
    end
    def setup_request(body)
      Net::HTTP::Post.new(uri, headers_for(body)).tap do |req|
        req.content_type = APPLICATION_JSON
        req.body = body
      end
    end
    def headers_for(body)
      BASE_HEADERS.merge(signature_headers(body))
    end
    private
    def log(message)
      logger.info(message)
    end
    def request_without_retries(body)
      req = setup_request(body)
      res = send_request(req)
      res.value
      log_response(SUCCESS, res)
    end
    def log_response(status, response)
      log("HTTP Request finished (#{status}): #{response.code} #{response.message}")
      log("Response body: #{response.body}")
    end
    def wait_for_retry_or_give_up(retry_count)
      if retry_count >= RETRY_LIMIT
        log("Retry limit exceeded, giving up")
        return false
      end
      sleep_time = 1 + (2**retry_count) + rand(2**retry_count)
      log("Waiting #{sleep_time}s for retry")
      sleep(sleep_time)
      true
    end
    def send_request(req)
      if ENV[DEBUG]
        puts "Request Data ".ljust(80, "=")
        JSON.parse(req.body) # will fail if req body is malformed
        print "req:       #{req.inspect}\n"
        print "uri:       #{uri}\n"
        print "hostname:  #{uri.hostname}\n"
        print "port:      #{uri.port}\n"
        print "headers:\n"
        req.to_hash.keys.sort.each do |h_key|
          print "  #{h_key}: #{req[h_key]}\n"
        end
        puts "End Request Data ".ljust(80, "=")
        http.set_debug_output($stderr)
      end
      http.start do |connection|
        connection.request(req)
      end
    ensure
      http.set_debug_output(nil)
    end
    def signature_headers(body)
      request_params = base_request_params.merge(body: body, timestamp: Time.now.utc.iso8601)
      sign_obj = Mixlib::Authentication::SignedHeaderAuth.signing_object(request_params)
      signed = sign_obj.sign(private_key)
      signed.inject({}) { |memo, kv| memo["#{kv[0].to_s.upcase}"] = kv[1]; memo }
    end
    def parse_key
      @private_key = OpenSSL::PKey::RSA.new(config.client_key)
    rescue OpenSSL::PKey::RSAError => e
      raise ConfigError, "Private key '#{config.client_key_path}' is malformed (#{e})"
    end
    def parse_uri
      @uri = URI(config.data_collector_url)
      unless VALID_PROTOCOLS.include?(uri.scheme)
        raise ConfigError, "Data Collector URL '#{config.data_collector_url}' is invalid: only 'http' and 'https' protocols are supported"
      end
      @uri
    rescue URI::InvalidURIError => e
      raise ConfigError, "Data Collector URL '#{config.data_collector_url}' is malformed (#{e})"
    end
    def set_base_request_params
      @base_request_params = {
        http_method: HTTP_METHOD,
        path: uri.path,
        host: "#{uri.host}:#{uri.port}",
        headers: BASE_HEADERS,
        user_id: config.client_name,
        proto_version: MIXLIB_AUTHN_PROTO_VERSION,
      }
    end
    def setup_http_client
      @http = Net::HTTP.new(uri.hostname, uri.port).tap do |h|
        h.open_timeout = 10
        h.read_timeout = 10
        h.ssl_timeout  = 10
        h.use_ssl      = uri.scheme == HTTPS_SCHEME
        h.verify_mode  = OpenSSL::SSL.const_get(config.ssl_verify_mode.upcase)
        h.ca_path      = config.ssl_ca_path if config.ssl_ca_path
        h.ca_file      = config.ssl_ca_file if config.ssl_ca_file
        h.cert_store   = OpenSSL::X509::Store.new
        h.cert_store.set_default_paths
        if !config.trusted_certs_dir.nil? && File.directory?(config.trusted_certs_dir)
          Dir.glob(File.join(config.trusted_certs_dir, "*.{crt,pem}")).each do |crt|
            begin
              h.cert_store.add_cert(OpenSSL::X509::Certificate.new(File.read(crt)))
            rescue OpenSSL::X509::StoreError => e
              print e.message if ENV[DEBUG]
            end
          end
        end
      end
    end
  end
end
## lib/automate_liveness_agent/liveness_update_sender.rb ##
require "time"
module AutomateLivenessAgent
  class LivenessUpdateSender
    attr_reader :config
    attr_reader :logger
    attr_reader :api_client
    UPDATE_INTERVAL_S = 60 * 30
    def initialize(config, logger)
      @config = config
      @logger = logger
      @api_client = APIClient.new(config, logger)
      api_client.load_and_verify_config
    end
    def log(message)
      logger.info(message)
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
## lib/automate_liveness_agent/main.rb ##
module AutomateLivenessAgent
  class Pipeline
    def initialize(implementation)
      @implementation = implementation
      @exit_code = 0
      @message = ""
    end
    def run(method_name)
      if @exit_code == 0
        @exit_code, @message = @implementation.public_send(method_name)
      end
      self
    end
    def finish
      if @exit_code != 0
        $stderr.print("#{@message}\n")
      end
      Kernel.exit(@exit_code)
    end
  end
  class Main
    USAGE = "Usage: automate-liveness-agent [config_file]".freeze
    SUCCESS = [ 0, "".freeze ].freeze
    attr_reader :argv
    attr_reader :config_path
    attr_reader :config
    attr_reader :logger
    def self.run(argv)
      new(argv).run
    end
    def initialize(argv)
      @argv = argv
      @config_path = nil
      @config = Config.new(nil)
      @logger = nil
    end
    def run
      Pipeline.new(self).
        run(:handle_argv).
        run(:load_config).
        run(:set_privileges).
        run(:setup_logger).
        run(:send_keepalives).
        finish
    end
    def handle_argv
      case argv.size
      when 0
        SUCCESS
      when 1
        if %w{ -h --help help }.include?(argv[0])
          [1, USAGE]
        else
          @config_path = argv[0]
          SUCCESS
        end
      else
        [1, USAGE]
      end
    end
    def load_config
      @config = Config.load(config_path)
      SUCCESS
    rescue ConfigError => e
      [ 1, e.to_s ]
    end
    def set_privileges
      unless config.unprivileged_gid.nil?
        Process.gid = config.unprivileged_gid
      end
      unless config.unprivileged_uid.nil?
        Process.uid = config.unprivileged_uid
      end
      SUCCESS
    rescue Errno::EPERM
      msg = "You must run as root to change privileges, or you can set unprivileged_uid and unprivileged_gid to null to disable privilege changes"
      [ 1,  msg ]
    end
    def setup_logger
      @logger = config.setup_logger
      SUCCESS
    rescue ConfigError => e
      [ 1, e.to_s ]
    end
    def send_keepalives
      a = LivenessUpdateSender.new(config, logger)
      a.main_loop
      SUCCESS
    rescue ConfigError => e
      [ 1, e.to_s ]
    end
  end
end
## bin/automate-liveness-agent ##
$LOAD_PATH.unshift(File.expand_path("../../lib", __FILE__))
AutomateLivenessAgent::Main.run(ARGV) unless ENV["AUTOMATE_LIVENESS_AGENT_SPECS_MODE"]

AUTOMATE_LIVENESS_AGENT
liveness_agent.gsub!('#!/usr/bin/env ruby', "#!#{Gem.ruby}")

windows = node['platform_family'] == "windows"

agent_dir      = Chef::Config.platform_specific_path('/var/opt/chef/')
agent_bin_dir  = ChefConfig::PathHelper.join(agent_dir, 'bin')
agent_etc_dir  = ChefConfig::PathHelper.join(agent_dir, 'etc')
agent_log_dir  = Chef::Config.platform_specific_path('/var/log/chef')
agent_bin      = ChefConfig::PathHelper.join(agent_bin_dir, 'automate-liveness-agent')
agent_conf     = ChefConfig::PathHelper.join(agent_etc_dir, 'config.json')
agent_username = 'chefautomate'
server_uri     = URI(Chef::Config[:chef_server_url])

init_script_path = value_for_platform(
  %i(debian ubuntu) => { default: '/etc/init.d/automate-liveness-agent' }
)

agent_user = user agent_username do
  home agent_dir
  shell '/bin/nologin' unless windows
end

[agent_bin_dir, agent_etc_dir, agent_log_dir].each do |dir|
  directory dir do
    recursive true
  end
end

file agent_bin do
  mode 0755
  owner 'root'
  content liveness_agent
end

file agent_conf do
  mode 0755
  owner 'root'
  content(
    lazy do
      {
        'chef_server_fqdn'   => server_uri.host,
        'client_key_path'    => Chef::Config[:client_key],
        'client_name'        => node.name,
        'data_collector_url' => Chef::Config[:data_collector][:server_url],
        'entity_uuid'        => Chef::JSONCompat.parse(Chef::FileCache.load('data_collector_metadata.json'))['node_uuid'],
        'install_check_file' => Gem.ruby,
        'org_name'           => Chef::Config[:data_collector][:organization] || server_uri.path.split('/').last,
        'unprivileged_uid'   => agent_user.uid,
        'unprivileged_gid'   => agent_user.gid,
      }.to_json
    end
  )
end

init_script = <<'INIT_SCRIPT'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          automate-liveness-agent
# Required-Start:    $local_fs $network $named $time $syslog
# Required-Stop:     $local_fs $network $named $time $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       foo
### END INIT INFO

SCRIPT="RUBYOPT='--disable-gems' RUBY_GC_HEAP_GROWTH_MAX_SLOTS=500 /var/opt/chef/bin/automate-liveness-agent /var/opt/chef/etc/config.json"
RUNAS=root

PIDFILE=/var/run/automate-liveness-agent.pid
LOGFILE=/var/log/chef/automate-liveness-agent.log

start() {
  if [ -f /var/run/$PIDNAME ] && kill -0 $(cat /var/run/$PIDNAME); then
    echo 'Service already running' >&2
    return 1
  fi
  echo 'Starting service…' >&2
  local CMD="$SCRIPT &> \"$LOGFILE\" & echo \$!"
  su -c "$CMD" $RUNAS > "$PIDFILE"
  echo 'Service started' >&2
}

stop() {
  if [ ! -f "$PIDFILE" ] || ! kill -0 $(cat "$PIDFILE"); then
    echo 'Service not running' >&2
    return 1
  fi
  echo 'Stopping service…' >&2
  kill -15 $(cat "$PIDFILE") && rm -f "$PIDFILE"
  echo 'Service stopped' >&2
}

uninstall() {
  echo -n "Are you really sure you want to uninstall this service? That cannot be undone. [yes|No] "
  local SURE
  read SURE
  if [ "$SURE" = "yes" ]; then
    stop
    rm -f "$PIDFILE"
    echo "Notice: log file is not be removed: '$LOGFILE'" >&2
    update-rc.d -f automate-liveness-agent remove
    rm -fv "$0"
  fi
}

case "$1" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  uninstall)
    uninstall
    ;;
  restart)
    stop
    start
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|uninstall}"
esac
INIT_SCRIPT

file init_script_path do
  content(init_script)
  mode 0755
  owner 'root'
end

service 'automate-liveness-agent' do
  action [:enable, :start]
end
