require "automate_liveness_agent/version"
require "automate_liveness_agent/config"
require "openssl"
require "net/http"
require "uri"
require "automate_liveness_agent/vendor/mixlib-authentication/lib/mixlib/authentication/signedheaderauth"

module AutomateLivenessAgent

  class APIClient

    MIXLIB_AUTHN_PROTO_VERSION = "1.3".freeze

    APPLICATION_JSON = "application/json".freeze

    HTTP_METHOD = "POST".freeze

    VALID_PROTOCOLS = %w{ http https }.freeze

    BASE_HEADERS = {
      "Accept" => APPLICATION_JSON,
      # TODO: should we configure the chef client version in the config?
      "X-Chef-Version" => "13.0.0".freeze,
      "User-Agent" => "Automate Liveness Agent #{AutomateLivenessAgent::VERSION}".freeze,
      "Content-Type" => APPLICATION_JSON,
    }.freeze

    DEBUG = "DEBUG".freeze

    # fix travis
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
      # HTTPResponse#value is the new HTTPResponse#error!
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

    # TODO: make sure we set the timeout stuff to reasonable values
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
              # The cert is probably invalid or already in the table
              print e.message if ENV[DEBUG]
            end
          end
        end
      end
    end
  end
end
