# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"

Dir["tasks/*"].each { |t| load t }

task :default => :spec
task :spec => :compile
RSpec::Core::RakeTask.new(:spec)
