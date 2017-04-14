require "automate_liveness_agent/version"
require "openssl"
require "mixlib/authentication/signedheaderauth"
require "net/http"
require "uri"

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

    def initialize(config)
      @config = config

      @api_client = APIClient.new(config)
    end

    # TODO: this should hit the server once and bubble errors up if it can't
    # connect.
    def verify_connection
      raise "TODO"
      # call api_client.verify to catch simple config errors
      # run one request, it should succeed
    end

    # TODO: this should catch errors, log them and move on
    def update
      @api_client.request(update_data)
    end

    def update_data
      name = "example_" + Time.now.to_i.to_s
      sprintf(DATA_TEMPLATE, name, name)
    end

  end

  class APIClient

    MIXLIB_AUTHN_PROTO_VERSION = "1.3".freeze

    APPLICATION_JSON = "application/json".freeze

    HTTP_METHOD = "POST".freeze

    BASE_HEADERS = {
      "Accept" => APPLICATION_JSON,
      # TODO: should we configure the chef client version in the config?
      "X-Chef-Version" => "13.0.0".freeze,
      "User-Agent" => "Automate Liveness Agent #{AutomateLivenessAgent::VERSION}".freeze,
      "Content-Type" => APPLICATION_JSON,
    }.freeze


    attr_reader :config
    attr_reader :uri
    attr_reader :base_request_params
    attr_reader :key_as_rsa

    def initialize(config)
      @config = config

      # TODO: move steps that can fail into a #verify! method:
      # * rsa key could be misformatted
      # * URI could be bad
      @key_as_rsa = OpenSSL::PKey::RSA.new(config.client_key)
      @uri = URI(config.chef_server_url)
      @base_request_params = {
        http_method: HTTP_METHOD,
        path: uri.path,
        host: "#{uri.host}:#{uri.port}",
        headers: BASE_HEADERS,
        user_id: config.client_name,
        proto_version: MIXLIB_AUTHN_PROTO_VERSION,
      }
    end

    def request(body)
      headers = BASE_HEADERS.merge(signature_headers(body))

      req = Net::HTTP::Post.new(uri, headers)
      req.content_type = APPLICATION_JSON
      req.body = body

      http = Net::HTTP.new(uri.hostname, uri.port)
      http.use_ssl = true

      # puts "* " * 40
      # require 'pp'
      # JSON.parse(body)
      # pp headers: headers
      # pp uri: uri
      # pp req: req.inspect
      # pp hostname: uri.hostname
      # pp port: uri.port
      # http.set_debug_output($stderr)

      res = http.start do |connection|
        connection.request(req)
      end
      # HTTPResponse#value is the new HTTPResponse#error!
      res.value
      puts res.body
    end

    private

    def signature_headers(body)
      request_params = base_request_params.merge(body: body, timestamp: Time.now.utc.iso8601)

      sign_obj = Mixlib::Authentication::SignedHeaderAuth.signing_object(request_params)
      signed = sign_obj.sign(key_as_rsa)
      signed.inject({}) { |memo, kv| memo["#{kv[0].to_s.upcase}"] = kv[1]; memo }
    end

  end
end
