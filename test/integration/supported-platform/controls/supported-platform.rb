org_name      = attribute("org_name", description: "The organization name")
host          = attribute("host", description: "The data collector host")
port          = attribute("port", description: "The data collector port")
root_url      = "http://#{host}:#{port}/organizations/#{org_name}"
reset_url     = "#{root_url}/reset-pings"
ping_url      = "#{root_url}/pings"
kitchen_dir   = attribute("kitchen_dir", default: "/tmp/kitchen")
windows       = attribute("windows", default: false)
client_rb     = File.join(kitchen_dir, "test-client.rb")
client_attrs  = File.join(kitchen_dir, "test-attrs.json")
sleep_seconds = attribute("sleep_seconds", default: "10")
sleep_cmd     = "sleep #{sleep_seconds}"
client_cmd    =
  if windows
    "chef-client -z -c #{client_rb} -j #{client_attrs}"
  else
    "INTERVAL=2 chef-client -z -c #{client_rb} -j #{client_attrs}"
  end

# reset the ping counter
describe http(reset_url) do
  its("status") { should cmp 200 }
  its("body") { should cmp "0" }
end

# converge the compiled recipe artifact
describe command(client_cmd) do
  its("exit_status") { should eq(0) }
end

# sleep to let the liveness agent send some pings
describe command(sleep_cmd) do
  its("exit_status") { should eq(0) }
end

# verify that the pings count has increased
describe http(ping_url) do
  its("body") { should_not cmp "0" }
  its("status") { should eq(200) }
end
