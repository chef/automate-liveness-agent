# coding: utf-8
# frozen_string_literal: true
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "automate_liveness_agent/version"

Gem::Specification.new do |spec|
  spec.name          = "automate-liveness-agent"
  spec.version       = AutomateLivenessAgent::VERSION
  spec.authors       = ["danielsdeleo"]
  spec.email         = ["dan@chef.io"]
  spec.license       = "Apache-2.0"

  spec.summary       = %q{Sends periodic keepalive messages to Chef Automate}
  spec.homepage      = "https://chef.io"

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata["allowed_push_host"] = "TODO: Set to 'http://mygemserver.com'"
  else
    raise "RubyGems 2.0 or newer is required to protect against " \
      "public gem pushes."
  end

  spec.files = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake", ">= 10.0"
  spec.add_development_dependency "rspec", ">= 3.0"
  spec.add_development_dependency "cookstyle"
  spec.add_development_dependency "chefstyle"
  spec.add_development_dependency "automatiek"
  # InSpec 2 has a blocking bug https://github.com/chef/inspec/issues/2822
  spec.add_development_dependency "inspec", "< 2.0"
  spec.add_development_dependency "kitchen-inspec"
  spec.add_development_dependency "kitchen-vagrant"
  spec.add_development_dependency "berkshelf"
end
