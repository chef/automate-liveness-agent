liveness_agent = <<'AUTOMATE_LIVENESS_AGENT'
#LIVENESS_AGENT
AUTOMATE_LIVENESS_AGENT

agent_dir = '/var/opt/chef/liveness_agent'
agent_bin_dir = ::File.join(agent_dir, 'bin')
agent_etc_dir = ::File.join(agent_dir, 'etc')
agent_bin = ::File.join(agent_bin_dir, 'automate-liveness-agent')
agent_conf = ::File.join(agent_etc_dir, 'config.json')

[agent_bin_dir, agent_etc_dir].each do |dir|
  directory dir do
    recursive true
  end
end

file agent_bin do
  content liveness_agent
end

server_uri = URI(Chef::Config[:chef_server_url])

file agent_conf do
  content({
    'client_key_path' => Chef::Config[:client_key_path],
    'client_name' => node.name,
    'chef_server_fqdn' => server_uri.host,
    'data_collector_url' => Chef::Config[:data_collector_url],
    'org_name' => Chef::Config[:data_collector][:organization] || server_uri.path.split('/').last,
    'entity_uuid' => Chef::JSONCompat.parse(
      Chef::FileCache.load('data_collector_metadata.json')
    )['node_uuid'],
    'unprivileged_uid' => 100,
    'unprivileged_gid' => 200
  }.to_json)
end

bash "start agent" do
  command "#{agent_bin} #{agent_conf}"
end
