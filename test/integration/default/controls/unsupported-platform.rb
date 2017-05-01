control "unsupported-platform" do
  impact 1
  title "verify that the agent recipe gracefully converges on unsupported platforms"

  # converge the compiled recipe artifact
  describe command("INTERVAL=2 chef-client -z -c /tmp/kitchen/test-client.rb -j /tmp/kitchen/test-attrs.json") do
    its("exit_status") { should eq(0) }
  end
end
