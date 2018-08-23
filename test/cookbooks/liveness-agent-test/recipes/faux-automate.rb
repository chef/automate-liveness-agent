# frozen_string_literal: true
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

apt_update

package 'bundler'

execute 'bundle install --binstubs' do
  cwd node['liveness-agent-test']['automate']['root_dir']
end

ruby_block 'kill-faux-automate' do
  block do
    begin
      pidfile = node['liveness-agent-test']['automate']['pidfile']
      Process.kill('HUP', ::File.read(pidfile).strip.to_i) if ::File.exist?(pidfile)
    # rubocop:disable Lint/HandleExceptions
    rescue Errno::ESRCH
    ensure
      FileUtils.rm(pidfile, force: true)
    end
  end
end

execute 'start-faux-automate' do
  environment 'RACK_ENV' => 'production'
  command "bin/rackup -D -P #{node['liveness-agent-test']['automate']['pidfile']}"
  cwd node['liveness-agent-test']['automate']['root_dir']
end
