require "bundler/gem_tasks"
require "rspec/core/rake_task"
require "automatiek"

task :default => :spec
RSpec::Core::RakeTask.new(:spec)

# Vendor Mixlib::Authentication and update all vendored 'require' entries
# with the vendored path.
Automatiek::RakeTask.new("mixlib-authentication") do |lib|
  lib.download = { github: "https://github.com/chef/mixlib-authentication" }
  lib.vendor_lib = "lib/automate_liveness_agent/vendor/mixlib-authentication"

  mixin = Module.new do
    def namespace_files
      require_target = vendor_lib.sub(%r{^(.+?/)?lib/}, "") << "/lib"
      relative_files = files.map do |f|
        Pathname.new(f).relative_path_from(Pathname.new(vendor_lib) / "lib").sub_ext("").to_s
      end
      process_files(
        /require (['"])(#{Regexp.union(relative_files)})/,
        "require \\1#{require_target}/\\2"
      )
    end
  end
  lib.send(:extend, mixin)
end
