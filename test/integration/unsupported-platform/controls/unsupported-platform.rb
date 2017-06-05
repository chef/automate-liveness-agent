# frozen_string_literal: true
kitchen_dir    = attribute("kitchen_dir", default: "/tmp/kitchen")
client_rb      = File.join(kitchen_dir, "test-client.rb")
client_attrs   = File.join(kitchen_dir, "test-attrs.json")
client_run_cmd = "INTERVAL=2 chef-client -z -c #{client_rb} -j #{client_attrs}"

# converge the compiled recipe artifact
describe command(client_run_cmd) do
  its("exit_status") { should eq(0) }
end
