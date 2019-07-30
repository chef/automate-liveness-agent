require 'chef/resource'
require 'chef/mixin/shell_out'
require 'chef/provider/user'

class ::Chef
  class Provider
    class User
      # macOS >= 10.14 introduced TCC restrictions that break the 'user' resource
      # on macOS. This resource and provider provide a bare-bones implementation
      # of a 'user' resource that is compatible with macOS 10.14 and 10.15.
      # The implementation is mostly borrowed from the patch to fix the upstream
      # 'user' resource in the chef-client: https://github.com/chef/chef/pull/8775
      #
      # The strange naming is so that we can be reasonably sure that we're not
      # going to collide with existing custom resources a user might include
      # during their client run. This is preferable to overriding the default
      # provider on the resource as we can't be sure which user resource is
      # going to be compiled and on which client version.
      class LivenessAgentMacOSUser < ::Chef::Provider::User
        provides :liveness_agent_macos_user

        attr_reader :user_plist

        def load_current_resource
          @current_resource = ::Chef::Resource::User::LivenessAgentMacOSUser.new(new_resource.username)
          current_resource.username(new_resource.username)

          reload_user_plist

          if user_plist
            current_resource.uid(user_plist[:uid][0])
            current_resource.gid(user_plist[:gid][0])
            current_resource.home(user_plist[:home][0])
            current_resource.shell(user_plist[:shell][0])
          else
            @user_exists = false
            logger.trace("#{new_resource} user does not exist")
          end

          current_resource
        end

        def reload_user_plist
          @user_plist = nil

          # Load the user information.
          begin
            user_xml = run_dscl('read', "/Users/#{new_resource.username}")
          rescue ::Chef::Exceptions::DsclCommandFailed
            return nil
          end

          return nil if user_xml.nil? || user_xml == ''

          @user_plist = Plist.new(::Plist.parse_xml(user_xml))
        end

        def create_user
          cmd = [-'-addUser', new_resource.username]
          cmd += ['-UID', new_resource.uid] if new_resource.property_is_set?(:uid)
          cmd += ['-shell', new_resource.shell]
          cmd += ['-home', new_resource.home] if new_resource.property_is_set?(:home)

          # sysadminctl doesn't exit with a non-zero exit code if it encounters
          # a problem. We'll check stderr and make sure we see that it finished
          # correctly.
          res = run_sysadminctl(cmd)
          unless res.downcase =~ /creating user/
            raise ::Chef::Exceptions::User, "error when creating user: #{res}"
          end

          # Wait for the user to show up in the ds cache
          wait_for_user

          if new_resource.property_is_set?(:gid)
            converge_by('create primary group ID') do
              run_dscl('create', "/Users/#{new_resource.username}", 'PrimaryGroupID', new_resource.gid)
            end
          end

          reload_user_plist
        end

        def compare_user
          %i{shell uid gid home}.any? { |m| diverged?(m) }
        end

        def manage_user
          %i{uid home}.each do |prop|
            logger.warn("cannot modify #{prop} on macOS >= 10.14") if diverged?(prop)
          end

          if diverged?(:shell)
            converge_by('alter shell') do
              run_dscl('create', "/Users/#{new_resource.username}", 'UserShell', new_resource.shell)
            end
          end

          if diverged?(:gid)
            converge_by('alter group membership') do
              run_dscl('create', "/Users/#{new_resource.username}", 'PrimaryGroupID', new_resource.gid)
            end
          end

          reload_user_plist
        end

        def remove_user
          cmd = ['-deleteUser', new_resource.username, '-secure']

          # sysadminctl doesn't exit with a non-zero exit code if it encounters
          # a problem. We'll check stderr and make sure we see that it finished
          res = run_sysadminctl(cmd)
          unless res.downcase =~ /deleting record|not found/
            raise ::Chef::Exceptions::User, "error deleting user: #{res}"
          end

          reload_user_plist
          @user_exists = false
        end

        def lock_user
          run_dscl('append', "/Users/#{new_resource.username}", 'AuthenticationAuthority', ';DisabledUser;')
          reload_user_plist
        end

        def unlock_user
          auth_string = user_plist[:auth_authority].reject! { |tag| tag == ';DisabledUser;' }.join.strip
          run_dscl('create', "/Users/#{new_resource.username}", 'AuthenticationAuthority', auth_string)
          reload_user_plist
        end

        def locked?
          user_plist[:auth_authority].any? { |tag| tag == ';DisabledUser;' }
        rescue
          false
        end

        def check_lock
          @locked = locked?
        end

        #
        # Methods
        #

        def diverged?(prop)
          prop = prop.to_sym

          case prop
          when :password
            password_diverged?
          when :gid
            user_group_diverged?
          when :secure_token
            secure_token_diverged?
          else
            # Other fields are have been set on current resource so just compare
            # them.
            new_resource.property_is_set?(prop) && (new_resource.send(prop) != current_resource.send(prop))
          end
        end

        # Attempt to resolve the group name, gid, and the action required for
        # associated group resource. If a group exists we'll modify it, otherwise
        # create it.
        def user_group_info
          @user_group_info ||= begin
            if new_resource.gid.is_a?(String)
              begin
                g = Etc.getgrnam(new_resource.gid)
                [g.name, g.gid.to_s, :modify]
              rescue
                [new_resource.gid, nil, :create]
              end
            else
              begin
                g = Etc.getgrgid(new_resource.gid)
                [g.name, g.gid.to_s, :modify]
              rescue
                [g.username, nil, :create]
              end
            end
          end
        end

        def user_group_diverged?
          return false unless new_resource.property_is_set?(:gid)

          group_name, group_id = user_group_info

          if current_resource.gid.is_a?(String)
            return current_resource.gid != group_name
          end

          current_resource.gid != group_id.to_i
        end

        def wait_for_user
          timeout = Time.now + 5

          loop do
            begin
              run_dscl('read', "/Users/#{new_resource.username}", 'ShadowHashData')
              break
            rescue ::Chef::Exceptions::DsclCommandFailed => e
              if Time.now < timeout
                sleep 0.1
              else
                raise ::Chef::Exceptions::User, e.message
              end
            end
          end
        end

        def run_dsimport(*args)
          shell_out!('dsimport', args)
        end

        def run_sysadminctl(args)
          # sysadminctl doesn't exit with a non-zero code when errors are encountered
          # and ouputs everything to STDERR instead of STDOUT and STDERR. Therefore we'll
          # return the STDERR and let the caller handle it.
          shell_out!('sysadminctl', args).stderr
        end

        def run_dscl(*args)
          result = shell_out('dscl', '-plist', '.', "-#{args[0]}", args[1..-1])
          return '' if (args.first =~ /^delete/) && (result.exitstatus != 0)
          raise(::Chef::Exceptions::DsclCommandFailed, "dscl error: #{result.inspect}") unless result.exitstatus == 0
          raise(::Chef::Exceptions::DsclCommandFailed, "dscl error: #{result.inspect}") if result.stdout =~ /No such key: /

          result.stdout
        end

        class Plist
          DSCL_PROPERTY_MAP = {
            uid: 'dsAttrTypeStandard:UniqueID',
            guid: 'dsAttrTypeStandard:GeneratedUID',
            gid: 'dsAttrTypeStandard:PrimaryGroupID',
            home: 'dsAttrTypeStandard:NFSHomeDirectory',
            shell: 'dsAttrTypeStandard:UserShell',
            comment: 'dsAttrTypeStandard:RealName',
            password: 'dsAttrTypeStandard:Password',
            auth_authority: 'dsAttrTypeStandard:AuthenticationAuthority',
            shadow_hash: 'dsAttrTypeNative:ShadowHashData',
            group_members: 'dsAttrTypeStandard:GroupMembers',
          }.freeze

          attr_accessor :plist_hash, :property_map

          def initialize(plist_hash = {}, property_map = DSCL_PROPERTY_MAP)
            @plist_hash = plist_hash
            @property_map = property_map
          end

          def get(key)
            return nil unless property_map.key?(key)

            plist_hash[property_map[key]]
          end
          alias_method :[], :get

          def set(key, value)
            return nil unless property_map.key?(key)

            plist_hash[property_map[key]] = [ value ]
          end
          alias_method :[]=, :set
        end
      end
    end
  end
end
