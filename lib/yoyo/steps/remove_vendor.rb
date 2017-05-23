module Yoyo
  module Steps
    # Remove a vendor
    class RemoveVendor < Yoyo::StepList
      include LdapManagerMixin

      attr_reader :username

      def initialize(manager)
        super

        @username = mgr.username
        if !@username.end_with?('-fcr') && !@username.end_with?('-voxpro')
          raise "Invalid vendor username; must end with '-fcr' or '-voxpro'"
        end
      end

      def init_steps
        LDAPMANAGER_HOSTS.each do |host|
          step "Remove SSH keys and groups from ldapmanager (host: #{host})" do
            complete? do
              @user = get_user_from_ldapmanager(host, mgr.username)
              @user['groups'].empty?
            end

            run do
              decred = @user.dup.update({
                public_keys: [],
                groups: [],
              })

              resp = ldapmanager_conn(host).post(path: "/api/v1/users/#{mgr.username}", body: JSON.dump(decred))
            end
          end
        end
      end
    end
  end
end
