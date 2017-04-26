RSpec.describe AutomateLivenessAgent::LivenessUpdateSender do
  let(:config) do
    AutomateLivenessAgent::Config.new("/etc/chef/agent.json").load_data(
      {
        "client_key_path"    => fixture("config/example.pem"),
        "client_name"        => "testnode.example.com",
        "chef_server_fqdn"   => "chef.example",
        "data_collector_url" => "https://chef.example/organizations/default/data-collector",
        "org_name"           => "default",
        "unprivileged_uid"   => 100,
        "unprivileged_gid"   => 100,
        "entity_uuid"        => "d4a509ca-bc15-422d-8a17-1f3903856bc4",
      }
    )
  end

  let(:time) { Time.now }

  before do
    allow(Time).to receive(:now).and_return(time)
  end

  subject { described_class.new(config) }

  describe "#update" do
    it "sends a valid payload" do
      expect(subject.api_client).to receive(:request).with(
        {
          "chef_server_fqdn" => "chef.example",
          "source" => "liveness_agent",
          "message_version" => "0.0.1",
          "message_type" => "node_ping",
          "organization_name" => "default",
          "node_name" => "testnode.example.com",
          "entity_uuid" => "d4a509ca-bc15-422d-8a17-1f3903856bc4",
          "@timestamp" => time.utc.iso8601,
        }.to_json
      )

      subject.update
    end
  end
end
