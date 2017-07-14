# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"

Dir["tasks/*"].each { |t| load t }

task :default => :travis

task :spec => :compile
RSpec::Core::RakeTask.new(:spec)

desc "Travis task group"
task :travis do
  if ENV["CHEFSTYLE"]
    Rake::Task["lint:chefstyle"].invoke
  elsif ENV["COOKSTYLE"]
    Rake::Task["lint:cookstyle"].invoke
  else
    Rake::Task["spec"].invoke
  end
end
