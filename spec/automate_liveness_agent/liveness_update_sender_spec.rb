RSpec.describe AutomateLivenessAgent::LivenessUpdateSender do

  let(:install_check_file) { nil }

  let(:config_data) do
    {
      "client_key_path"    => fixture("config/example.pem"),
      "client_name"        => "testnode.example.com",
      "chef_server_fqdn"   => "chef.example",
      "data_collector_url" => "https://chef.example/organizations/default/data-collector",
      "org_name"           => "default",
      "unprivileged_uid"   => 100,
      "unprivileged_gid"   => 100,
      "entity_uuid"        => "d4a509ca-bc15-422d-8a17-1f3903856bc4",
      "install_check_file" => install_check_file,
    }
  end

  let(:config) do
    AutomateLivenessAgent::Config.new("/etc/chef/agent.json").load_data(config_data)
  end

  let(:time) { Time.now }

  before do
    allow(Time).to receive(:now).and_return(time)
  end

  subject(:update_sender) { described_class.new(config) }

  describe "#update" do
    it "sends a valid payload" do
      expect(subject.api_client).to receive(:request).with(
        {
          "chef_server_fqdn" => "chef.example",
          "source" => "liveness_agent",
          "message_version" => "0.0.1",
          "event_type" => "node_ping",
          "organization_name" => "default",
          "node_name" => "testnode.example.com",
          "entity_uuid" => "d4a509ca-bc15-422d-8a17-1f3903856bc4",
          "@timestamp" => time.utc.iso8601,
        }.to_json
      )

      subject.update
    end
  end

  describe "checking for uninstall" do

    context "when the uninstall check isn't configured" do

      it "skips the uninstall check" do
        update_sender # File.exist? gets called when we evaluate the let bindings
        expect(File).to_not receive(:exist?)
        expect(update_sender.chef_uninstalled?).to be(false)
      end

    end

    context "when the install check is enabled" do

      context "and the install_check_file exists" do

        let(:install_check_file) { fixture("config/install_check_file") }

        it "checks the file's existence and continues" do
          expect(update_sender.chef_uninstalled?).to be(false)
        end

      end

      context "and the install_check_file doesn't exist" do

        let(:install_check_file) { fixture("config/install_check_file_missing") }

        it "detects an uninstall" do
          expect(update_sender.chef_uninstalled?).to be(true)
        end

      end

    end

  end
end
