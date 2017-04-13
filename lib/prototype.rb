# TODO: remove this code or replace with something more useful after the
# prototyping phase is done.
#

$LOAD_PATH.unshift(File.expand_path("..", __FILE__))

require "automate_liveness_agent/main"

include AutomateLivenessAgent
Main.run(["./config.json"])
