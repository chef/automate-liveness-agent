# reset the ping counter
describe http("http://localhost:9292/reset-pings") do
  its("status") { should eq(200) }
  its("body") { should eq("0") }
end

# converge the compiled recipe artifact
describe command("INTERVAL=2 cd /tmp/kitchen && chef-client -z -c ./test-client.rb -j ./test-attrs.json") do
  its("exit_status") { should eq(0) }
end

# sleep for 5 seconds to let the liveness agent send some pings
describe command("sleep 5") do
  its("exit_status") { should eq(0) }
end

# verify that the pings count has increased
describe http("http://localhost:9292/pings") do
  its("status") { should eq(200) }
  its("body") { should be > 0 }
end
