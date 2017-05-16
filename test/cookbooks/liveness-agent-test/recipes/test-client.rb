kitchen_root = platform_family?('windows') ? :: File.join(ENV['TEMP'], 'kitchen') : '/tmp/kitchen'
host         = node['liveness-agent-test']['automate']['host']
port         = node['liveness-agent-test']['automate']['port']
org_name     = node['liveness-agent-test']['automate']['org_name']
server_url   = "http://#{host}:#{port}/organizations/#{org_name}/data-collector"

# Create a client.rb that will hit our fake chef automate
client_content = ::File.read(::File.join(kitchen_root, 'client.rb'))
client_content << "\ndata_collector['server_url'] = '#{server_url}'"
client_content << "\ndata_collector['mode'] = :both"
client_content << "\ndata_collector['organization'] = '#{org_name}'"

file ::File.join(kitchen_root, 'test-client.rb') do
  content client_content
end

# Create an client attributes file that'll run our compiled recipe
attrs = Chef::JSONCompat.parse(::File.read(::File.join(kitchen_root, 'dna.json')))
attrs['run_list'] = ['recipe[liveness-agent-test::compiled-recipe]']

file ::File.join(kitchen_root, 'test-attrs.json') do
  content Chef::JSONCompat.to_json_pretty(attrs)
end

# Make sure that /var/log/chef exists and is writable by the vagrant user. If
# we don't do this then inspec won't run our specs on macOS.
directory '/var/log/chef' do
  recursive true
  owner 'vagrant'
  only_if { node['platform_family'] == 'mac_os_x' }
end
