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

# rubocop:disable Style/SpaceAroundOperators

# exit early if we're running on an unsupported platform
return unless %w(
  amazon
  debian
  fedora
  freebsd
  mac_os_x
  oracle
  rhel
  solaris2
  suse
  windows
).include?(node['platform_family'])

# only support solaris 10 and 11
return if platform?('solaris2') && node['platform_version'] !~ /^5.(10|11)$/
liveness_agent = <<'AUTOMATE_LIVENESS_AGENT'
#LIVENESS_AGENT
AUTOMATE_LIVENESS_AGENT
liveness_agent.gsub!('#!/usr/bin/env ruby', "#!#{Gem.ruby}")

agent_dir         = Chef::Config.platform_specific_path('/var/opt/chef/')
agent_bin_dir     = ChefConfig::PathHelper.join(agent_dir, 'bin')
agent_etc_dir     = ChefConfig::PathHelper.join(agent_dir, 'etc')
agent_log_dir     = Chef::Config.platform_specific_path('/var/log/chef')
agent_log_file    = ChefConfig::PathHelper.join(agent_log_dir, 'automate-liveness-agent.log')
agent_bin         = ChefConfig::PathHelper.join(agent_bin_dir, 'automate-liveness-agent')
agent_conf        = ChefConfig::PathHelper.join(agent_etc_dir, 'config.json')
agent_username    = 'chefautomate'
run_interval      = 1 # only windows
server_uri        = URI(Chef::Config[:chef_server_url])
trusted_certs_dir = File.directory?(Chef::Config[:trusted_certs_dir]) ? Chef::Config[:trusted_certs_dir] : nil

agent_service_name = value_for_platform_family(
  %i(
    amazon
    debian
    fedora
    oracle
    rhel
    suse
  )            => 'automate-liveness-agent',
  %i(mac_os_x) => 'io.chef.automate.liveness.agent',
  %i(freebsd)  => 'automate_liveness_agent',
  %i(solaris2) => 'automatelivenessagent',
  %i(windows)  => nil
)
agent_init_script_path = value_for_platform_family(
  %i(
    amazon
    debian
    fedora
    rhel
    oracle
    solaris2
    suse
  )            => "/etc/init.d/#{agent_service_name}",
  %i(freebsd)  => "/etc/rc.d/#{agent_service_name}",
  %i(mac_os_x) => "/Library/LaunchDaemons/#{agent_service_name}.plist",
  %i(windows)  => nil
)
admin_user = value_for_platform_family(
  %i(
    amazon
    debian
    fedora
    freebsd
    mac_os_x
    oracle
    rhel
    solaris2
    suse
  )           => 'root',
  %i(windows) => 'administrator'
)
admin_group = value_for_platform_family(
  %i(
    debian
    rhel
    amazon
    fedora
    oracle
    suse
  )            => 'root',
  %i(
    freebsd
    mac_os_x
  )            => 'wheel',
  %i(solaris2) => 'sys',
  %i(windows)  => 'Administrators'
)
agent_user_shell = value_for_platform_family(
  %i(
    amazon
    debian
    fedora
    freebsd
    mac_os_x
    oracle
    rhel
    suse
  )            => '/sbin/nologin',
  %i(solaris2) => '/bin/false',
  %i(windows)  => nil
)

user agent_username do
  home agent_dir
  shell agent_user_shell
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
  owner admin_user
  group admin_group
  content liveness_agent
  notifies :restart, "service[#{agent_service_name}]" unless platform?('windows')
end

file agent_conf do
  mode 0755
  owner admin_user
  group admin_group
  content(
    lazy do
      Chef::JSONCompat.to_json_pretty(
        'chef_server_fqdn'    => server_uri.host,
        'client_key_path'     => Chef::Config[:client_key],
        'client_name'         => node.name,
        'data_collector_url'  => Chef::Config[:data_collector][:server_url],
        'entity_uuid'         => Chef::JSONCompat.parse(Chef::FileCache.load('data_collector_metadata.json'))['node_uuid'],
        'install_check_file'  => Gem.ruby,
        'org_name'            => Chef::Config[:data_collector][:organization] || server_uri.path.split('/').last,
        'unprivileged_uid'    => platform?('windows') ? nil : Etc.getpwnam(agent_username).uid,
        'unprivileged_gid'    => platform?('windows') ? nil : Etc.getpwnam(agent_username).gid,
        'log_file'            => agent_log_file,
        'ssl_verify_mode'     => Chef::Config[:ssl_verify_mode],
        'ssl_ca_file'         => Chef::Config[:ssl_ca_file],
        'ssl_ca_path'         => Chef::Config[:ssl_ca_path],
        'trusted_certs_dir'   => trusted_certs_dir,
        'scheduled_task_mode' => platform?('windows') || platform?('mac_os_x')
      )
    end
  )

  notifies :restart, "service[#{agent_service_name}]" unless platform?('windows')
end

if platform?('windows')

  # In windows we run things as as a scheduled task instead of a daemon
  # This avoids the code overhead of a service, and isn't too inefficient since we run infrequently
  scheduled_task_script = ChefConfig::PathHelper.join(agent_bin_dir, 'automate_liveness_agent_task.ps1')

  # We hide configuration details in this script; it was too much to pass on the schtasks command line
  file scheduled_task_script do
    mode 0755
    owner admin_user
    group admin_group
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
schtasks /create /f /sc minute /mo #{run_interval} /tn "Chef Liveness Agent" /ru SYSTEM /rl HIGHEST /tr "powershell.exe -windowstyle hidden #{scheduled_task_script}"
EOH
  end

  # with windows we exit after we start the scheduled task
  return
end

agent_init_script =
  if platform?('freebsd')
    <<'RC_SCRIPT'
#!/bin/sh
#
# PROVIDE: automate_liveness_agent
# REQUIRE: LOGIN cleanvar
# KEYWORD: shutdown

. /etc/rc.subr

name="automate_livenss_agent"
rcvar="automate_livenss_agent_enable"
pidfile="/var/run/automate-liveness-agent.pid"
start_cmd="start_automate_liveness_agent"
stop_cmd="stop_automate_liveness_agent"
restart_cmd="restart_automate_liveness_agent"
status_cmd="check_automate_liveness_agent_status"
extra_commands="status"

load_rc_config $name

start_automate_liveness_agent() {
 if [ -f "$pidfile" ] && kill -0 `cat "$pidfile"`; then
    echo 'Service already running' >&2
    return 1
  fi
  echo 'Starting service…' >&2

  RUBYOPT="--disable-gems";
  RUBY_GC_HEAP_GROWTH_MAX_SLOTS=500;
  export RUBYOPT
  export RUBY_GC_HEAP_GROWTH_MAX_SLOTS
  /var/opt/chef/bin/automate-liveness-agent /var/opt/chef/etc/config.json
}

stop_automate_liveness_agent() {
  local pid=`cat $pidfile`
  if [ ! -f "$pidfile" ] || ! kill -0 "$pid"; then
    echo 'Service not running' >&2
    return 1
  fi
  echo 'Stopping service…' >&2
  kill -15 "$pid"
  rm -f "$pidfile"
  echo 'Service stopped' >&2
}

restart_automate_liveness_agent() {
  stop_automate_liveness_agent
  start_automate_liveness_agent
}

check_automate_liveness_agent_status() {
  if [ -f "$pidfile" ] && kill -0 `cat "$pidfile"`; then
    echo 'Service is running' >&2
    return 0
  else
    echo 'Service is not running' >&2
    return 1
  fi
}

run_rc_command "$1"
RC_SCRIPT
  elsif platform?('mac_os_x')
    <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>EnvironmentVariables</key>
        <dict>
                <key>RUBYOPT</key>
                <string>--disable-gems</string>
                <key>RUBY_GC_HEAP_GROWTH_MAX_SLOTS</key>
                <string>500</string>
        </dict>
        <key>GroupName</key>
        <string>wheel</string>
        <key>KeepAlive</key>
        <dict>
	              <key>SuccessfulExit</key>
	              <true/>
        </dict>
        <key>Label</key>
        <string>io.chef.automate.liveness.agent</string>
        <key>ProgramArguments</key>
        <array>
                <string>/var/opt/chef/bin/automate-liveness-agent</string>
                <string>/var/opt/chef/etc/config.json</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>StartInterval</key>
        <integer>1800</integer>
        <key>UserName</key>
        <string>root</string>
</dict>
</plist>
PLIST
  elsif platform?('solaris2')
    <<'INIT_SCRIPT'
#!/sbin/sh

SCRIPT="RUBYOPT='--disable-gems' RUBY_GC_HEAP_GROWTH_MAX_SLOTS=500 /var/opt/chef/bin/automate-liveness-agent /var/opt/chef/etc/config.json"

PIDFILE=/var/run/automate-liveness-agent.pid

start_agent() {
  if [ -f "$PIDFILE" ] && kill -0 `cat "$PIDFILE"`; then
    echo 'Service already running' >&2
    return 0
  fi
  echo 'Starting service...' >&2
  eval "$SCRIPT"
  echo 'Service started' >&2
}

stop_agent() {
  if [ ! -f "$PIDFILE" ]; then
    echo 'Service not running' >&2
    return 0
  fi

  echo 'Stopping service...' >&2
  kill -15 `cat "$PIDFILE"`
  rm -f "$PIDFILE"
  echo 'Service stopped' >&2
}

case "$1" in
  'start')
    start_agent
    ;;
  'stop')
    stop_agent
    ;;
  'restart')
    stop_agent
    start_agent
    ;;
  *)
    echo "Usage: $0 {start|stop|restart}"
esac
INIT_SCRIPT
  else # linux
    <<'INIT_SCRIPT'
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
  if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE"); then
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

status() {
  if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE"); then
    echo 'Service is running' >&2
    return 0
  else
    echo 'Service is not running' >&2
    return 1
  fi
}

case "$1" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  status)
    status
    ;;
  restart)
    stop
    start
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status}"
esac
INIT_SCRIPT
  end

file agent_init_script_path do
  content(agent_init_script)
  mode 0744
  owner admin_user
  group admin_group
  notifies :restart, "service[#{agent_service_name}]" unless platform?('windows')
end

if platform?('solaris2')
  service_manifest_path = '/var/svc/manifest/application/chef/automatelivenessagent.xml'

  directory ::File.dirname(service_manifest_path) do
    owner admin_user
    group admin_group
    recursive true
  end

  bash 'import-solaris-service-manifest' do
    action :nothing
    notifies :restart, "service[#{agent_service_name}]"
    code <<"SCRIPT"
if svccfg list | grep automatelivenessagent; then
  svcadmin disable automatelivenessagent
  svcadmin delete automatelivenessagent
fi

svccfg import #{service_manifest_path}

# sleep until the service manager knows about our new service
while ! svcs -x automatelivenessagent; do
  sleep 2
done
SCRIPT
  end

  file service_manifest_path do
    mode 0744
    owner admin_user
    group admin_group
    notifies :run, 'bash[import-solaris-service-manifest]', :immediately
    content <<'SERVICE_MANIFEST'
<?xml version='1.0'?>
<!DOCTYPE service_bundle SYSTEM "/usr/share/lib/xml/dtd/service_bundle.dtd.1">

<service_bundle type='manifest' name='chef:automatelivenessagent'>
<service
    name='application/chef/automatelivenessagent'
    type='service'
    version='1'>

    <create_default_instance enabled='false' />
    <single_instance/>

    <dependency
      name='multi-user-server'
      grouping='optional_all'
      type='service'
      restart_on='none'>
        <service_fmri value='svc:/milestone/multi-user-server' />
    </dependency>

    <exec_method
        type='method'
        name='start'
        exec='/etc/init.d/automatelivenessagent %m'
        timeout_seconds='20' />

    <exec_method
        type='method'
        name='restart'
        exec='/etc/init.d/automatelivenessagent %m'
        timeout_seconds='20' />

    <exec_method
        type='method'
        name='stop'
        exec='/etc/init.d/automatelivenessagent %m'
        timeout_seconds='20' />

    <template>
        <common_name>
            <loctext xml:lang='C'>Chef Automate Liveness Agent</loctext>
        </common_name>
    </template>
</service>
</service_bundle>
SERVICE_MANIFEST
  end
end

service agent_service_name do
  supports(
    start: true,
    stop: true,
    restart: true,
    status: true,
    uninstall: false,
    reload: false
  )

  if platform?('mac_os_x')
    # There's no need to "start" the service on MacOS. The liveness agent is
    # configured in scheduled_task_mode and runs via launchd on a scheduled
    # 30 minute interval. {start,restart,stop} are all supported but
    # unnecessary.
    action :enable
  else
    action %i(enable start)
  end
end
