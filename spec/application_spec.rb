# Top level application behaviors. This is here to give us a start.
RSpec.describe "Liveness Agent Application" do

  it "sends an authenticated HTTP request every 30 minutes"

  it "reads a JSON(???) copy of the client config"

  it "reads config files and key and then drops privileges"

  it "supports the rubies used by Chef 12 and Chef 13"

  it "can run in the foreground"

  it "can run daemonized"

  it "detects a chef-client uninstall and shuts down"

  it "can run in a stress test mode that is designed to surface memory leaks"

end
