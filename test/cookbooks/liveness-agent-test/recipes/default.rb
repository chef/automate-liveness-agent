# In order to test the compiled recipe artifact we have to actually run
# the chef-client with the compiled recipe and verify that the liveness
# agent is actually sending pings. To do this we'll utilize a fake
# Chef Automate service chef-zero to run our compiled recipe artifact.

node.override['liveness-agent-test']['kitchen_root'] = platform_family?('windows') ? :: File.join(ENV['TEMP'], 'kitchen') : '/tmp/kitchen'
