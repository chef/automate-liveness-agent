kitchen_root = node['liveness-agent-test']['kitchen_root']

# Create a client.rb that will hit our fake chef automate
client_content = ::File.read(::File.join(kitchen_root, 'client.rb'))
client_content << "\ndata_collector['server_url'] = 'http://localhost:9292/data-collector/v0'"
client_content << "\ndata_collector['mode'] = :both"
client_content << "\ndata_collector['organization'] = 'default'"

file ::File.join(kitchen_root, 'test-client.rb') do
  content client_content
end

# Create an client attributes file that'll run our compiled recipe
attrs = Chef::JSONCompat.parse(::File.read(::File.join(kitchen_root, 'dna.json')))
attrs['run_list'] = ['recipe[liveness-agent-test::compiled-recipe]']

file ::File.join(kitchen_root, 'test-attrs.json') do
  content Chef::JSONCompat.to_json_pretty(attrs)
end
