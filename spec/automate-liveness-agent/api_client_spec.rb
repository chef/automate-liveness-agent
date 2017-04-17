require "automate_liveness_agent/api_client"

RSpec.describe AutomateLivenessAgent::APIClient do

  let(:config_path) { "/dummy/path/to/config.json" }

  let(:client_key_path) { fixture("config/example.pem") }

  let(:chef_server_url) { "https://chef.example/organizations/default" }

  let(:config_data) do
    {
      "chef_server_url"  => chef_server_url,
      "client_key_path"  => client_key_path,
      "client_name"      => "testnode.example.com",
      "unprivileged_uid" => 100,
      "unprivileged_gid" => 100,
    }
  end

  let(:config) { AutomateLivenessAgent::Config.new(config_path).load_data(config_data) }

  let(:api_client) { described_class.new(config) }

  it "is created with a config object" do
    expect(api_client.config).to eq(config)
  end

  describe "loading and verifying config" do

    context "when all config values are present and valid" do

      before do
        api_client.load_and_verify_config
      end

      it "sets the private key" do
        expect(api_client.private_key).to be_a(OpenSSL::PKey::RSA)
        expect(api_client.private_key.to_s).to eq(File.read(fixture("config/example.pem")))
      end

      it "sets the API service URI" do
        expect(api_client.uri).to be_a(URI::Generic)
        expect(api_client.uri.to_s).to eq("https://chef.example/organizations/default")
      end

      # TODO: this would break the prototype b/c the real endpoint isn't
      # available for testing yet. Obviously we need this for the production
      # version.
      it "sets the URI path to the data collector endpoint"

      it "sets the base request params for auth" do
        expected = {
          http_method: "POST",
          path: "/organizations/default",
          host: "chef.example:443",
          headers: described_class::BASE_HEADERS,
          user_id: "testnode.example.com",
          proto_version: described_class::MIXLIB_AUTHN_PROTO_VERSION,
        }
        expect(api_client.base_request_params).to eq(expected)
      end

      it "configures a Net::HTTP client" do
        expect(api_client.http.use_ssl?).to be(true)
        expect(api_client.http.open_timeout).to eq(10)
        expect(api_client.http.read_timeout).to eq(10)
        expect(api_client.http.ssl_timeout).to eq(10)
      end

      it "configures OpenSSL verify modes"

      it "configures OpenSSL cert paths"

      it "configures OpenSSL for trusted certs"

    end

    # NOTE: The config class is expected to make sure the client key path is
    # configured and exists, and that the chef server URL is configured.
    # It doesn't validate the content of either of them, though.

    context "when the private key is not valid" do

      let(:client_key_path) { fixture("config/bad_key.pem") }

      # Force the `let` bindings to get evaluated so we know the errors don't
      # occur inside initialize
      before { api_client }

      it "raises a ConfigError" do
        expected_message = "Private key '#{client_key_path}' is malformed (Neither PUB key nor PRIV key: nested asn1 error)"
        expect { api_client.load_and_verify_config }.
          to raise_error(AutomateLivenessAgent::ConfigError, expected_message)
      end

    end

    context "when the Chef Server URL is not a valid URI" do

      let(:chef_server_url) { "Lobster Bisque" }

      it "raises a ConfigError"do
        expected_message = "Chef Server URL 'Lobster Bisque' is malformed (bad URI(is not URI?): Lobster Bisque)"
        expect { api_client.load_and_verify_config }.
          to raise_error(AutomateLivenessAgent::ConfigError, expected_message)
      end

    end

    context "when the Chef Server URL is a valid URI with a bizzaro protocol" do

      let(:chef_server_url) { "telnet://towel.blinkenlights.nl" }

      it "raises a ConfigError" do
        expected_message = "Chef Server URL 'telnet://towel.blinkenlights.nl' is invalid: only 'http' and 'https' protocols are supported"
        expect { api_client.load_and_verify_config }.
          to raise_error(AutomateLivenessAgent::ConfigError, expected_message)
      end

    end

  end

  describe "Making HTTP Requests" do

    let(:req_data) { '{"foo": "bar"}' }

    before do
      api_client.load_and_verify_config
    end

    context "when the request succeeds" do

      let(:connection) { instance_double("Net::HTTP") }

      let(:http_ok_response) do
        Net::HTTPOK.new("1.1", 200, "OK").tap do |r|
          allow(r).to receive(:read_body).and_return("")
        end
      end

      before do
        allow(api_client.http).to receive(:start).and_yield(connection)
        allow(connection).to receive(:request).and_return(http_ok_response)
        allow(api_client).to receive(:log)
      end

      it "makes the request" do
        api_client.request(req_data)
      end

    end

    context "when the request fails" do

      let(:connection) { instance_double("Net::HTTP") }

      before do
        allow(api_client.http).to receive(:start).and_yield(connection)
        allow(connection).to receive(:request).and_raise(exception)
        allow(api_client).to receive(:log)
        expect(api_client).to receive(:sleep).exactly(5).times
      end

      context "with a non-2XX HTTP response" do

        let(:message) { "Bad Request" }

        let(:response_body) { '{"error": "invalid JSON"}' }

        let(:error_response) do
          instance_double(Net::HTTPClientError,
                          code: "400",
                          message: message,
                          body: response_body)
        end

        let(:exception) do
          Net::HTTPServerException.new(message, error_response)
        end

        it "retries 5 times then gives up" do
          api_client.request(req_data)
        end
      end

      context "with a local connection error" do

        let(:exception) { SocketError }

        it "retries 5 times then gives up" do
          api_client.request(req_data)
        end

      end

      context "with a remote connection refused" do

        let(:exception) { Errno::ECONNREFUSED }

        it "retries 5 times then gives up" do
          api_client.request(req_data)
        end

      end

      context "with a timeout" do

        let(:exception) { Timeout::Error }

        it "retries 5 times then gives up" do
          api_client.request(req_data)
        end

      end

      context "with an OpenSSL error" do

        let(:exception) { OpenSSL::SSL::SSLError }

        it "retries 5 times then gives up" do
          api_client.request(req_data)
        end

      end

    end

  end

end
