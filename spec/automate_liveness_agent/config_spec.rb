require "automate_liveness_agent/config"

RSpec.describe AutomateLivenessAgent::Config do

  let(:config_path) { "/path/to/config.json" }

  subject(:config) { described_class.new(config_path) }

  it "is created with a config file path" do
    expect(config.config_path).to eq(config_path)
  end

  context "when created with a nil config path" do

    let(:config_path) { nil }

    it "sets the config path to the default" do
      expect(config.config_path).to eq("/etc/chef/config.json")
    end

  end

  context "when created with a relative config path" do

    let(:config_path) { "path/to/config.json" }

    it "expands the path relative to CWD" do
      expect(config.config_path).to eq(File.join(Dir.pwd, "path/to/config.json"))
    end

  end

  describe "attempting to load an invalid config file" do

    let(:error) do
      raised_exception =
        begin
          config.load_config_file
          "expected a ConfigError exception but it didn't get raised"
        rescue => e
          e
        end
      expect(raised_exception).to be_a_kind_of(AutomateLivenessAgent::ConfigError)
      raised_exception
    end

    context "when the config file doesn't exist" do

      let(:config_path) { fixture("no_such_thing.json") }

      it "raises a ConfigError" do
        expect(error.message).to eq("Config file '#{config_path}' does not exist or is not readable")
      end

    end

    context "when the config file isn't readable" do

      let(:config_path) { fixture("config/empty_file.json") }

      before do
        expect(File).to receive(:readable?).with(config_path).and_return(false)
      end

      it "raises a ConfigError" do
        expect(error.message).to include("Config file '#{config_path}' is not readable (current uid =")
      end

    end

    context "when the config file is empty" do

      let(:config_path) { fixture("config/empty_file.json") }

      it "raises a ConfigError" do
        expect(error.message).to eq("Config file '#{config_path}' is empty")
      end

    end

    context "when the config file isn't valid JSON" do

      let(:config_path) { fixture("config/invalid_json.json") }

      it "raises a ConfigError" do
        expect(error.message).to eq("Config file '#{config_path}' has a JSON formatting error")
      end

    end

    describe "when the config file doesn't contain all required values" do

      BASE_CONFIG_DATA =
        {
          "chef_server_url"  => "https://chef.example/organizations/default",
          "client_key_path"  => "/etc/chef/client.pem",
          "client_name"      => "testnode.example.com",
          "unprivileged_uid" => 100,
          "unprivileged_gid" => 100,
        }

      BASE_CONFIG_DATA.each_key do |key|

        context "when key '#{key}' is not present" do

          let(:config_data) { BASE_CONFIG_DATA.dup.tap { |d| d.delete(key) } }

          let(:expected_message) { "Config file '#{config_path}' is missing mandatory setting(s): '#{key}'" }

          it "raises a ConfigError" do
            expect { config.apply_config_values(config_data) }.
              to raise_error(AutomateLivenessAgent::ConfigError, expected_message )
          end

        end
      end

      context "when multiple required settings are missing" do
        let(:config_data) { {} }

        let(:expected_message) do
          "Config file '#{config_path}' is missing mandatory setting(s): "\
            "'chef_server_url','client_key_path','client_name','unprivileged_uid','unprivileged_gid'"
        end

        it "raises a ConfigError" do
          expect { config.apply_config_values(config_data) }.
            to raise_error(AutomateLivenessAgent::ConfigError, expected_message )
        end
      end

    end

  end

  context "after the config file is loaded" do

    let(:config_path) { fixture("config/valid_config.json") }

    before do
      config.load_config_file
    end

    it "has a Chef Server URL" do
      expect(config.chef_server_url).to eq("https://chef.example/organizations/default")
    end

    it "has a client key path" do
      expect(config.client_key_path).to eq("/etc/chef/client.pem")
    end

    it "has a client name" do
      expect(config.client_name).to eq("testnode.example.com")
    end

    it "has a UID to drop privileges to" do
      expect(config.unprivileged_uid).to eq(100)
    end

    it "has a GID to drop privileges to" do
      expect(config.unprivileged_gid).to eq(200)
    end

  end

  describe "loading the client key" do


    let(:config_data) do
      {
        "chef_server_url"  => "https://chef.example/organizations/default",
        "client_key_path"  => client_key_path,
        "client_name"      => "testnode.example.com",
        "unprivileged_uid" => 100,
        "unprivileged_gid" => 100,
      }
    end

    context "when the key file doesn't exist or isn't readable" do

      let(:client_key_path) { fixture("config/no_such_key.pem") }

      before do
        config.apply_config_values(config_data)
      end

      it "raises a ConfigError" do

        expect { config.load_client_key }.to raise_error(AutomateLivenessAgent::ConfigError)
      end

    end

    context "when the key exists and is readable" do

      let(:client_key_path) { fixture("config/example.pem") }

      before do
        config.apply_config_values(config_data)
        config.load_client_key
      end

      it "loads the client key to memory" do
        expect(config.client_key).to start_with("-----BEGIN RSA PRIVATE KEY-----")
      end

    end

  end
end

