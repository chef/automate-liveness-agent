require 'chef/resource/user'

class ::Chef
  class Resource
    class User
      # See macos/provider for a full description of this resource/provider
      class LivenessAgentMacOSUser < ::Chef::Resource::User
        resource_name :liveness_agent_macos_user

        provides :liveness_agent_macos_user

        # Overload gid to set our default gid to 20, the macOS "staff" group.
        # We also allow a string group name here which we'll attempt to resolve
        # or create in the provider.
        property :gid, [Integer, String], description: 'The numeric group identifier.', default: 20, coerce: (lambda do |gid|
          begin
            Integer(gid) # Try and coerce a group id string into an integer
          rescue
            gid # assume we have a group name
          end
        end)

        # Overload home so we set our default.
        property :home, String, description: 'The user home directory', default: lazy { "/Users/#{name}" }
      end
    end
  end
end
