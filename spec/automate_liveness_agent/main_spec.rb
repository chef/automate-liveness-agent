require "automate_liveness_agent/main"

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

    context "when config loading is successful" do

      it "loads the config"

    end

    context "when config loading fails" do

      it "exits 1 with the error message"

    end

  end

  it "sends an authenticated HTTP request every 30 minutes"

  it "reads a JSON(???) copy of the client config"

  it "reads config files and key and then drops privileges"

  it "supports the rubies used by Chef 12 and Chef 13"

  it "can run in the foreground"

  it "can run daemonized"

  it "detects a chef-client uninstall and shuts down"

  it "can run in a stress test mode that is designed to surface memory leaks"

end

