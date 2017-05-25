module Yoyo
  module Steps
    # Steps to add a new vendor user
    class AddVendor < Yoyo::StepList
      include LdapManagerMixin

      attr_reader :username, :full_name

      def initialize(manager)
        super

        @username = mgr.username
        if !Yoyo::Vendor::is_vendor?(@username)
          raise "Invalid vendor username; must end with '-fcr' or '-voxpro'"
        end

        @full_name = mgr.full_name
        raise "Must provide a full name" if @full_name.empty?
      end

      def init_steps
        step "Add new user to LDAP using ldapmanager (prod)" do
          host = 'ldapmanager.corp.stripe.com'
          complete? do
            user_exists_in_ldapmanager?(host)
          end

          run do
            create_request = {
              username: username,
              name: full_name,

              groups: ['vendor'],
              pubkeys: [],
            }
            resp = ldapmanager_conn(host).post(path: '/api/v1/users', body: JSON.dump(create_request))
            raise "error creating user:\n#{resp.inspect}" if resp.status != 200
          end
        end

        step "Add new user to LDAP using ldapmanager (QA)" do
          host = 'ldapmanager.qa.corp.stripe.com'
          prod_host = 'ldapmanager.corp.stripe.com'

          complete? do
            user_exists_in_ldapmanager?(host)
          end

          run do
            unix_uid = get_user_from_ldapmanager(prod_host, username)['uid']
            raise "invalid uid: #{unix_uid.inspect}" unless unix_uid.is_a?(Integer)

            create_request = {
              username: username,
              name: full_name,
              uid: unix_uid,

              groups: ['vendor'],
              pubkeys: [],
            }
            resp = ldapmanager_conn(host).post(path: '/api/v1/users', body: JSON.dump(create_request))
            raise "error creating user:\n#{resp.inspect}" if resp.status != 200
          end
        end
      end
    end
  end
end
