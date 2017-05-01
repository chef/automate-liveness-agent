RSpec.describe AutomateLivenessAgent::Main do

  let(:argv) { [] }

  subject(:application) { described_class.new(argv) }

  it "has the argv it was created with" do
    expect(application.argv).to eq(argv)
  end

  describe "handling CLI arguments" do

    let(:result) { application.handle_argv }

    context "when no CLI arguments are given" do

      it "leaves the config path as nil so Config class can set it" do
        expect(result).to eq([0, ""])
        expect(application.config_path).to be(nil)
      end

    end

    context "when a config file path is given" do

      let(:argv) { %w{ /path/to/config.json } }

      it "sets the config path to the given value" do
        expect(result).to eq([0, ""])
        expect(application.config_path).to eq("/path/to/config.json")
      end

    end

    context "when -h is given" do

      let(:argv) { %w{ -h } }

      it "exits 1 with usage" do
        expect(result).to eq([1, described_class::USAGE])
      end

    end

    context "when --help is given" do

      let(:argv) { %w{ -h } }

      it "exits 1 with usage" do
        expect(result).to eq([1, described_class::USAGE])
      end

    end

    context "when 'help' is given" do

      let(:argv) { %w{ -h } }

      it "exits 1 with usage" do
        expect(result).to eq([1, described_class::USAGE])
      end

    end
  end

  describe "loading the config" do

    let(:argv) { %w{ /path/to/config.json } }

    before { application.handle_argv }

    context "when config loading is successful" do

      it "loads the config" do
        expect(AutomateLivenessAgent::Config).to receive(:load).with(argv.first)
        expect(application.load_config).to eq(described_class::SUCCESS)
      end

    end

    context "when config loading fails" do

      it "exits 1 with the error message" do
        expect(AutomateLivenessAgent::Config).to receive(:load).
          with(argv.first).
          and_raise(AutomateLivenessAgent::ConfigError, "explanation of problem")
        expected = [ 1, "explanation of problem" ]
        expect(application.load_config).to eq(expected)
      end

    end

  end

  describe "changing privileges" do

    let(:config_data) do
      {
        "chef_server_fqdn" => "",
        "client_key_path" => fixture("config/example.pem"),
        "client_name" => "",
        "data_collector_url" => "",
        "entity_uuid" => "",
        "org_name" => "",
        "unprivileged_uid" => uid,
        "unprivileged_gid" => gid,
      }
    end

    before do
      application.config.load_data(config_data)
    end

    context "when privilege dropping is disabled" do

      let(:uid) { nil }
      let(:gid) { nil }

      it "does not change uid or gid" do
        expect(Process).to_not receive(:uid=)
        expect(Process).to_not receive(:gid=)
        application.set_privileges
      end

    end

    context "when configured to drop privileges" do

      let(:uid) { 100 }
      let(:gid) { 200 }

      it "sets uid and gid" do
        expect(Process).to receive(:uid=).with(100)
        expect(Process).to receive(:gid=).with(200)
        application.set_privileges
      end

      it "resues permissions errors and returns an error message" do
        expect(File).to receive(:open).with("/var/run/automate-liveness-agent.pid", "w", 0644)
        expect(Process).to receive(:gid=).with(200).and_raise(Errno::EPERM, "not allowed")
        expected_message = "You must run as root to change privileges, or you can set unprivileged_uid and unprivileged_gid to null to disable privilege changes"
        expect(application.set_privileges).to eq([1, expected_message])
      end

    end

  end

  describe "running the main loop" do

    let(:update_sender) { instance_double("AutomateLivenessAgent::LivenessUpdateSender") }

    before { application.setup_logger }

    context "with a valid configuration" do

      it "runs the update sender's main loop" do
        expect(AutomateLivenessAgent::LivenessUpdateSender).to receive(:new).
          with(application.config, application.logger).
          and_return(update_sender)
        expect(update_sender).to receive(:main_loop)
        expect(application.send_keepalives).to eq(described_class::SUCCESS)
      end

    end

    context "with an invalid key or URI" do

      it "exits 1 with the error message" do
        expect(AutomateLivenessAgent::LivenessUpdateSender).to receive(:new).
          with(application.config, application.logger).
          and_return(update_sender)
        expect(update_sender).to receive(:main_loop).
          and_raise(AutomateLivenessAgent::ConfigError, "explanation of problem")
        expected = [ 1, "explanation of problem" ]
        expect(application.send_keepalives).to eq(expected)
      end

    end

    context "in scheduled task mode" do

      let(:config_data) do
        {
          "chef_server_fqdn" => "",
          "client_key_path" => fixture("config/example.pem"),
          "client_name" => "",
          "data_collector_url" => "",
          "entity_uuid" => "",
          "org_name" => "",
          "unprivileged_uid" => nil,
          "unprivileged_gid" => nil,
          "scheduled_task_mode" => true,
        }
      end

      before do
        application.config.load_data(config_data)
      end

      it "tells LivenessUpdateSender to make a single update instead of looping" do
        expect(AutomateLivenessAgent::LivenessUpdateSender).to receive(:new).
          with(application.config, application.logger).
          and_return(update_sender)
        expect(update_sender).to receive(:update)
        expect(application.send_keepalives).to eq(described_class::SUCCESS)
      end

    end

  end

end

