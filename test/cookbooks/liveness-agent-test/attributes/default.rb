default['liveness-agent-test']['automate'].tap do |automate|
  automate['root_dir'] = '/var/opt/delivery'
  automate['gemfile'] = '/var/opt/delivery/Gemfile'
  automate['config_ru'] = '/var/opt/delivery/config.ru'
  automate['app'] = '/var/opt/delivery/app.rb'
  automate['pidfile'] = '/var/run/automate.pid'
  automate['org_name'] = 'default'
  automate['host'] = '192.168.33.66'
  automate['port'] = 9292
end
