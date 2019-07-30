# frozen_string_literal: false
RSpec.describe AutomateLivenessAgent::Config do

  BASE_CONFIG_DATA =
    {
    "chef_server_fqdn" => "chef.example",
    "client_key_path" => fixture("config/example.pem"),
    "client_name" => "testnode.example.com",
    "data_collector_url" => "https://chef.example/organizations/default/data-collector",
    "entity_uuid" => "d4a509ca-bc15-422d-8a17-1f3903856bc4",
    "org_name" => "default",
    "unprivileged_uid" => 100,
    "unprivileged_gid" => 100,
  }.freeze

  let(:config_path) { "/path/to/config.json" }

  subject(:config) { described_class.new(config_path) }

  it "is created with a config file path" do
    expect(config.config_path).to eq(config_path)
  end

  it "disables scheduled task mode by default" do
    expect(config.scheduled_task_mode).to be(false)
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

      BASE_CONFIG_DATA.each_key do |key|

        context "when key '#{key}' is not present" do

          let(:config_data) { BASE_CONFIG_DATA.dup.tap { |d| d.delete(key) } }

          let(:expected_message) { "Config file '#{config_path}' is missing mandatory setting(s): \"#{key}\"" }

          it "raises a ConfigError" do
            expect { config.apply_config_values(config_data) }
              .to raise_error(AutomateLivenessAgent::ConfigError, expected_message )
          end

        end
      end

      context "when multiple required settings are missing" do
        let(:config_data) { {} }

        let(:expected_message) do
          "Config file '#{config_path}' is missing mandatory setting(s): " <<
            BASE_CONFIG_DATA.keys.map { |k| "\"#{k}\"" }.join(",")
        end

        it "raises a ConfigError" do
          expect { config.apply_config_values(config_data) }
            .to raise_error(AutomateLivenessAgent::ConfigError, expected_message )
        end
      end

    end

  end

  describe "configuring the logger" do

    let(:logger) { config.setup_logger }

    let(:log_dev) { logger.instance_variable_get(:@logdev) }

    let(:log_io) { log_dev.dev }

    let(:configured_log_file) { nil }

    let(:config_data) do
      BASE_CONFIG_DATA.merge("log_file" => configured_log_file)
    end

    before do
      config.load_data(config_data)
    end

    context "when not set or set to nil" do

      it "logs to stdout" do
        expect(logger).to be_a_kind_of(Logger)
        expect(log_io).to eq(STDOUT)
      end

    end

    context "when set to STDOUT" do

      let(:configured_log_file) { "STDOUT" }

      it "logs to stdout" do
        expect(logger).to be_a_kind_of(Logger)
        expect(log_io).to eq(STDOUT)
      end

    end

    context "when set to STDERR" do

      let(:configured_log_file) { "STDERR" }

      it "logs to stderr" do
        expect(logger).to be_a_kind_of(Logger)
        expect(log_io).to eq(STDERR)
      end

    end

    context "when set to a file" do

      context "when the file's directory doesn't exist" do

        let(:configured_log_file) { fixture("no_such_path/exists/log") }

        it "fails with a config error" do
          message = "Log directory '#{fixture("no_such_path/exists")}' (inferred from log_path config) does not exist or is not a directory"
          expect { config.setup_logger }.to raise_error(AutomateLivenessAgent::ConfigError, message)
        end

      end

      context "when the file's directory isn't writable" do

        let(:configured_log_file) { fixture("logger/logs") }

        it "fails with a config error" do
          expect(File).to receive(:writable?).with(fixture("logger")).and_return(false)
          message = "Log directory '#{fixture("logger")}' (inferred from log_path config) is not writable by current user (uid: #{Process.uid})"
          expect { config.setup_logger }.to raise_error(AutomateLivenessAgent::ConfigError, message)
        end

      end

      context "when the log file itself exists and isn't writable" do

        let(:configured_log_file) { fixture("logger/logs") }

        it "fails with a config error" do
          expect(File).to receive(:writable?).with(fixture("logger")).and_return(true)
          expect(File).to receive(:exist?).with(fixture("logger/logs")).and_return(true)
          expect(File).to receive(:writable?).with(fixture("logger/logs")).and_return(false)
          message = "Log file '#{fixture("logger/logs")}' (set by log_path config) is not writable by current user (uid: #{Process.uid})"
          expect { config.setup_logger }.to raise_error(AutomateLivenessAgent::ConfigError, message)
        end

      end

      context "when the file permissions are all ok" do

        def nuke_files
          Dir[fixture("logger/*")].each { |f| File.unlink(f) }
        end

        let(:configured_log_file) { fixture("logger/logs") }

        let(:max_size) { log_dev.instance_variable_get(:@shift_size) }

        before { nuke_files }
        after { nuke_files }

        context "without stress mode" do

          it "opens the log and configures a max size of 512k and 2 files to rotate" do
            expect(log_io.path).to eq(configured_log_file)
            expect(max_size).to eq(512 * 1024)
          end

        end

        context "when stress mode is enabled" do

          around do |e|
            ENV["LOGGER_STRESS_MODE"] = "1"
            e.run
            ENV.delete("LOGGER_STRESS_MODE")
          end

          it "configures a max size of 2k" do
            expect(log_io.path).to eq(configured_log_file)
            expect(max_size).to eq(2 * 1024)
          end

        end
      end
    end
  end

  context "after the config file is loaded" do

    let(:config_path) { fixture("config/valid_config.json") }

    before do
      config.load_config_file
    end

    it "has a client key path" do
      expect(config.client_key_path).to eq("/etc/chef/client.pem")
    end

    it "has a client name" do
      expect(config.client_name).to eq("testnode.example.com")
    end

    it "has a Chef Server FQDN" do
      expect(config.chef_server_fqdn).to eq("chef.example")
    end

    it "has a Data Collector URL" do
      expect(config.data_collector_url).to eq("https://chef.example/organizations/default/data-collector")
    end

    it "has an org name" do
      expect(config.org_name).to eq("default")
    end

    it "has a UID to drop privileges to" do
      expect(config.unprivileged_uid).to eq(100)
    end

    it "has a GID to drop privileges to" do
      expect(config.unprivileged_gid).to eq(200)
    end

    it "has a scheduled task mode setting" do
      expect(config.scheduled_task_mode).to be(true)
    end

  end

  describe "loading the client key" do

    let(:config_data) do
      {
        "client_key_path" => client_key_path,
        "client_name" => "testnode.example.com",
        "chef_server_fqdn" => "chef.example",
        "data_collector_url" => "https://chef.example/organizations/default/data-collector",
        "org_name" => "deafault",
        "entity_uuid" => "d4a509ca-bc15-422d-8a17-1f3903856bc4",
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

  describe "setting the interval" do
    context "when the interval is an integer" do
      let(:config_data) do
        BASE_CONFIG_DATA.merge("interval" => 60)
      end

      before do
        config.apply_config_values(config_data)
      end

      it "sets the interval" do
        expect(config.interval).to eq(60)
      end
    end

    context "when the interval is a string of numbers" do
      let(:config_data) do
        BASE_CONFIG_DATA.merge("interval" => "65")
      end

      before do
        config.apply_config_values(config_data)
      end

      it "sets the interval" do
        expect(config.interval).to eq(65)
      end
    end

    context "when the interval is a string that contains characters" do
      let(:config_data) do
        BASE_CONFIG_DATA.merge("interval" => "not seconds")
      end

      it "raises an error" do
        expect { config.apply_config_values(config_data) }.to raise_error(AutomateLivenessAgent::ConfigError, /is not an integer/)
      end
    end

    context "when the interval is nil" do
      let(:config_data) do
        BASE_CONFIG_DATA.merge("interval" => nil)
      end

      before do
        config.apply_config_values(config_data)
      end

      it "sets the interval to nil" do
        expect(config.interval).to eq(nil)
      end
    end
  end
end
