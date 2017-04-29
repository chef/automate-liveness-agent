require 'inspec'

# reset the ping counter
describe http("http://localhost:9292/reset-pings") do
  its("status") { should cmp 200 }
  its("body") { should cmp "0"  }
end

# converge the compiled recipe artifact
describe command("INTERVAL=2 chef-client -z -c /tmp/kitchen/test-client.rb -j /tmp/kitchen/test-attrs.json") do
  its("exit_status") { should eq(0) }
end

# sleep to let the liveness agent send some pings
describe command("sleep 10") do
  its("exit_status") { should eq(0) }
end

# verify that the pings count has increased
describe http("http://localhost:9292/pings") do
  its("body") { should_not cmp "0" }
  its("status") { should eq(200) }
end
