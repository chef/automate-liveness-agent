# frozen_string_literal: false
RSpec.describe AutomateLivenessAgent::APIClient do

  let(:config_path) { "/dummy/path/to/config.json" }

  let(:client_key_path) { fixture("config/example.pem") }

  let(:data_collector_url) { "https://chef.example/organizations/default/data-collector" }

  let(:ssl_verify_mode) { "verify_peer" }

  let(:ssl_ca_file) { nil }

  let(:ssl_ca_path) { nil }

  let(:trusted_certs_dir) { nil }

  let(:config_data) do
    {
      "chef_server_fqdn"   => "chef.example",
      "client_key_path"    => client_key_path,
      "client_name"        => "testnode.example.com",
      "data_collector_url" => data_collector_url,
      "entity_uuid"        => "d4a509ca-bc15-422d-8a17-1f3903856bc4",
      "org_name"           => "default",
      "ssl_verify_mode"    => ssl_verify_mode,
      "ssl_ca_file"        => ssl_ca_file,
      "ssl_ca_path"        => ssl_ca_path,
      "trusted_certs_dir"  => trusted_certs_dir,
      "unprivileged_uid"   => 100,
      "unprivileged_gid"   => 100,
    }
  end

  let(:config) { AutomateLivenessAgent::Config.new(config_path).load_data(config_data) }

  let(:api_client) { described_class.new(config, Logger.new(nil)) }

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
        expect(api_client.uri.to_s).to eq("https://chef.example/organizations/default/data-collector")
      end

      it "sets the base request params for auth" do
        expected = {
          http_method: "POST",
          path: "/organizations/default/data-collector",
          host: "chef.example:443",
          headers: described_class::BASE_HEADERS,
          user_id: "testnode.example.com",
          proto_version: described_class::MIXLIB_AUTHN_PROTO_VERSION,
        }
        expect(api_client.base_request_params).to eq(expected)
      end

      it "configures a Net::HTTP client" do
        expect(api_client.http).to be_instance_of(Net::HTTP)
      end

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
        expect { api_client.load_and_verify_config }
          .to raise_error(AutomateLivenessAgent::ConfigError, expected_message)
      end

    end

    context "when the Data Collector URL is not a valid URI" do

      let(:data_collector_url) { "Lobster Bisque" }

      it "raises a ConfigError" do
        expected_message = "Data Collector URL 'Lobster Bisque' is malformed (bad URI(is not URI?): Lobster Bisque)"
        expect { api_client.load_and_verify_config }
          .to raise_error(AutomateLivenessAgent::ConfigError, expected_message)
      end

    end

    context "when the Chef Server URL is a valid URI with a bizzaro protocol" do

      let(:data_collector_url) { "telnet://towel.blinkenlights.nl" }

      it "raises a ConfigError" do
        expected_message = "Data Collector URL 'telnet://towel.blinkenlights.nl' is invalid: only 'http' and 'https' protocols are supported"
        expect { api_client.load_and_verify_config }
          .to raise_error(AutomateLivenessAgent::ConfigError, expected_message)
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

  describe "setting up the HTTP Client" do
    context "default config" do
      it "uses and verifies SSL" do
        api_client.load_and_verify_config
        expect(api_client.http.use_ssl?).to eq(true)
        expect(api_client.http.verify_mode).to eq(OpenSSL::SSL::VERIFY_PEER)
      end
    end

    context "ssl_verify_mode verify_none" do
      let(:ssl_verify_mode) { "verify_none" }

      it "disables SSL verification" do
        api_client.load_and_verify_config
        expect(api_client.http.verify_mode).to eq(OpenSSL::SSL::VERIFY_NONE)
      end
    end

    context "invalid ssl mode" do
      let(:ssl_verify_mode) { "verify_beer" }

      it "raises an error" do
        expect { api_client.load_and_verify_config }
          .to raise_error(AutomateLivenessAgent::ConfigError, /not a valid ssl_verify_mode/)
      end
    end

    context "with a trusted_certs_dir" do
      let(:trusted_cert_path) { fixture("trusted_certs/chef-example.crt") }
      let(:trusted_cert) { OpenSSL::X509::Certificate.new(File.read(trusted_cert_path)) }
      let(:trusted_certs_dir) { File.dirname(trusted_cert_path) }

      it "verifies trusted trusted certs" do
        api_client.load_and_verify_config
        expect(api_client.http.cert_store.verify(trusted_cert)).to be_truthy
      end
    end

    context "invalid trusted_certs_dir" do
      let(:trusted_certs_dir) { "/not/a/real/directory" }

      it "raises an error" do
        expect { api_client.load_and_verify_config }
          .to raise_error(AutomateLivenessAgent::ConfigError, /not a directory/)
      end
    end

    context "with a ca file" do
      let(:ssl_ca_file) { fixture("config/example.pem") }

      it "sets the ca file" do
        api_client.load_and_verify_config
        expect(api_client.http.ca_file).to eq(ssl_ca_file)
      end
    end

    context "invalid ca file" do
      let(:ssl_ca_file) { "/not/a/ca/file" }

      it "raises an error" do
        expect { api_client.load_and_verify_config }
          .to raise_error(AutomateLivenessAgent::ConfigError, /does not exist/)
      end
    end

    context "with a ca path" do
      let(:ssl_ca_path) { fixture("config") }

      it "sets the ca path" do
        api_client.load_and_verify_config
        expect(api_client.http.ca_path).to eq(ssl_ca_path)
      end
    end

    context "invalid ca path" do
      let(:ssl_ca_path) { "/not/a/ca/path" }

      it "raises an error" do
        expect { api_client.load_and_verify_config }
          .to raise_error(AutomateLivenessAgent::ConfigError, /not a directory/)
      end
    end
  end
end
