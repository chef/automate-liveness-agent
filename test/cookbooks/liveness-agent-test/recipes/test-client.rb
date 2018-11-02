# frozen_string_literal: true
kitchen_root = platform_family?("windows") ? :: File.join(ENV["TEMP"], "kitchen") : "/tmp/kitchen"
host         = node["liveness-agent-test"]["automate"]["host"]
port         = node["liveness-agent-test"]["automate"]["port"]
org_name     = node["liveness-agent-test"]["automate"]["org_name"]
server_url   = "http://#{host}:#{port}/organizations/#{org_name}/data-collector"

# Create a client.rb that will hit our fake chef automate
client_content = ::File.read(::File.join(kitchen_root, "client.rb"))
client_content << "\ndata_collector['server_url'] = '#{server_url}'"
client_content << "\ndata_collector['mode'] = :both"
client_content << "\ndata_collector['organization'] = '#{org_name}'"
client_content << "\nlog_location \"c:\\\\chef-client-\#{Time.now.to_i}.log\""

file ::File.join(kitchen_root, "test-client.rb") do
  content client_content
end

# Create an client attributes files so we can test our stable recipe and our
# current recipe.
current_attrs = Chef::JSONCompat.parse(::File.read(::File.join(kitchen_root, "dna.json")))
stable_attrs = current_attrs.dup

current_attrs["run_list"] = ["recipe[liveness-agent-test::compiled-recipe]"]
stable_attrs["run_list"] = ["recipe[liveness-agent-test::stable-compiled-recipe]"]

file ::File.join(kitchen_root, "test-stable-attrs.json") do
  content Chef::JSONCompat.to_json_pretty(stable_attrs)
end

file ::File.join(kitchen_root, "test-current-attrs.json") do
  content Chef::JSONCompat.to_json_pretty(current_attrs)
end

# Make sure that /var/log/chef exists and is writable by the vagrant user. If
# we don't do this then inspec won't run our specs on macOS.
directory "/var/log/chef" do
  recursive true
  owner "vagrant"
  only_if { node["platform_family"] == "mac_os_x" }
end
