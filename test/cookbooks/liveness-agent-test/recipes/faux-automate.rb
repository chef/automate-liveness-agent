directory node['liveness-agent-test']['automate']['root_dir'] do
  recursive true
end

cookbook_file node['liveness-agent-test']['automate']['gemfile'] do
  source 'automate/Gemfile'
end

cookbook_file node['liveness-agent-test']['automate']['config_ru'] do
  source 'automate/config.ru'
end

cookbook_file node['liveness-agent-test']['automate']['app'] do
  source 'automate/app.rb'
end

execute 'bundle install --binstubs' do
  cwd node['liveness-agent-test']['automate']['root_dir']
end

ruby_block 'kill-faux-automate' do
  block do
    pidfile = node['liveness-agent-test']['automate']['pidfile']
    Process.kill('HUP', ::File.read(pidfile).strip.to_i) if ::File.exist?(pidfile)
  end
end

execute 'start-faux-automate' do
  command "bin/rackup -D -P #{node['liveness-agent-test']['automate']['pidfile']}"
  cwd node['liveness-agent-test']['automate']['root_dir']
end
