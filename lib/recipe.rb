#  Copyright 2017 Chef Software, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

# exit early if we're running on an unsupported platform
return unless %w(debian rhel amazon windows).include?(node['platform_family'])

liveness_agent = <<'AUTOMATE_LIVENESS_AGENT'
#LIVENESS_AGENT
AUTOMATE_LIVENESS_AGENT
liveness_agent.gsub!('#!/usr/bin/env ruby', "#!#{Gem.ruby}")

run_interval      = 1 # only windows
install_user      = platform?('windows') ? 'administrator' : 'root'
install_group     = platform?('windows') ? 'Administrators' : 'root'
agent_dir         = Chef::Config.platform_specific_path('/var/opt/chef/')
agent_bin_dir     = ChefConfig::PathHelper.join(agent_dir, 'bin')
agent_etc_dir     = ChefConfig::PathHelper.join(agent_dir, 'etc')
agent_log_dir     = Chef::Config.platform_specific_path('/var/log/chef')
agent_log_file    = ChefConfig::PathHelper.join(agent_log_dir, 'automate-liveness-agent.log')
agent_bin         = ChefConfig::PathHelper.join(agent_bin_dir, 'automate-liveness-agent')
agent_conf        = ChefConfig::PathHelper.join(agent_etc_dir, 'config.json')
agent_username    = 'chefautomate'
server_uri        = URI(Chef::Config[:chef_server_url])
trusted_certs_dir = File.directory?(Chef::Config[:trusted_certs_dir]) ? Chef::Config[:trusted_certs_dir] : nil

init_script_path = value_for_platform_family(
  %i(debian rhel amazon) => '/etc/init.d/automate-liveness-agent'
)

user agent_username do
  home agent_dir
  shell '/bin/nologin' unless platform?('windows')
end

[agent_bin_dir, agent_etc_dir].each do |dir|
  directory dir do
    recursive true
  end
end

directory agent_log_dir do
  owner agent_username
  recursive true
end

file agent_bin do
  mode 0755
  owner install_user
  group install_group
  content liveness_agent
end

file agent_conf do
  mode 0755
  owner install_user
  group install_group
  content(
    lazy do
      Chef::JSONCompat.to_json_pretty(
        'chef_server_fqdn'   => server_uri.host,
        'client_key_path'    => Chef::Config[:client_key],
        'client_name'        => node.name,
        'data_collector_url' => Chef::Config[:data_collector][:server_url],
        'entity_uuid'        => Chef::JSONCompat.parse(Chef::FileCache.load('data_collector_metadata.json'))['node_uuid'],
        'install_check_file' => Gem.ruby,
        'org_name'           => Chef::Config[:data_collector][:organization] || server_uri.path.split('/').last,
        'unprivileged_uid'   => platform?('windows') ? nil : Etc.getpwnam(agent_username).uid,
        'unprivileged_gid'   => platform?('windows') ? nil : Etc.getpwnam(agent_username).gid,
        'log_file'           => agent_log_file,
        'ssl_verify_mode'    => Chef::Config[:ssl_verify_mode],
        'ssl_ca_file'        => Chef::Config[:ssl_ca_file],
        'ssl_ca_path'        => Chef::Config[:ssl_ca_path],
        'trusted_certs_dir'  => trusted_certs_dir,
        'scheduled_task_mode' => platform?('windows')
      )
    end
  )

  notifies :restart, 'service[automate-liveness-agent]' unless platform?('windows')
end

if platform?('windows')

  # In windows we run things as as a scheduled task instead of a daemon
  # This avoids the code overhead of a service, and isn't too inefficient since we run infrequently
  scheduled_task_script = ChefConfig::PathHelper.join(agent_bin_dir, "automate_liveness_agent_task.ps1")

  # We hide configuration details in this script; it was too much to pass on the schtasks command line
  file scheduled_task_script do
    mode 0755
    owner install_user
    group install_group
    content <<"SCRIPT_BODY"
# powershell script to run the Chef automate liveness agent as a scheduled task\r\n
$env:RUBYOPT = "--disable-gems"\r\n
$env:RUBY_GC_HEAP_GROWTH_MAX_SLOTS = 500\r\n
#{Gem.ruby} #{agent_bin} #{agent_conf}\r\n
SCRIPT_BODY
    # debugging add Get-Date -Format g | Out-File c:\\chef\\script.log\r\n to script above
  end

  # Set up scheduled task; this is idempotent because scheduled tasks replace ones with same name
  powershell_script 'Setup scheduled task' do
    # If we are running powershell > 3, there's a nice API to do this, but 2008r2 doesn't provide that
    code <<-EOH
schtasks /create /f /sc minute /mo #{run_interval} /tn "Chef Liveness Agent" /tr "powershell.exe -windowstyle hidden #{scheduled_task_script}"
EOH
  end

else # not windows

  init_script = <<'INIT_SCRIPT'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          automate-liveness-agent
# Required-Start:    $local_fs $network $named $time $syslog
# Required-Stop:     $local_fs $network $named $time $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       foo
### END INIT INFO

SCRIPT="RUBYOPT='--disable-gems' RUBY_GC_HEAP_GROWTH_MAX_SLOTS=500 /var/opt/chef/bin/automate-liveness-agent /var/opt/chef/etc/config.json"
RUNAS=root

PIDFILE=/var/run/automate-liveness-agent.pid

start() {
  if [ -f $PIDFILE ] && kill -0 $(cat $PIDFILE); then
    echo 'Service already running' >&2
    return 1
  fi
  echo 'Starting service…' >&2
  su -c "$SCRIPT" $RUNAS
  echo 'Service started' >&2
}

stop() {
  if [ ! -f "$PIDFILE" ] || ! kill -0 $(cat "$PIDFILE"); then
    echo 'Service not running' >&2
    return 1
  fi
  echo 'Stopping service…' >&2
  kill -15 $(cat "$PIDFILE")
  rm -f "$PIDFILE"
  echo 'Service stopped' >&2
}

uninstall() {
  echo -n "Are you really sure you want to uninstall this service? That cannot be undone. [yes|No] "
  local SURE
  read SURE
  if [ "$SURE" = "yes" ]; then
    stop
    rm -f "$PIDFILE"
    update-rc.d -f automate-liveness-agent remove
    rm -fv "$0"
  fi
}

case "$1" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  uninstall)
    uninstall
    ;;
  restart)
    stop
    start
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|uninstall}"
esac
INIT_SCRIPT

  file init_script_path do
    content(init_script)
    mode 0755
    owner 'root'
    notifies :restart, 'service[automate-liveness-agent]'
  end

  service 'automate-liveness-agent' do
    supports(
      start: true,
      stop: true,
      restart: true,
      uninstall: true,
      status: false,
      reload: false
    )
    action [:enable, :start]
  end

end # not windows
