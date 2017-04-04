module Yoyo

  # Mixin moodule that contains helper functions for interacting with ldapmanager.
  module LdapManagerMixin
    LDAPMANAGER_HOSTS = ['ldapmanager.corp.stripe.com', 'ldapmanager.qa.corp.stripe.com']

    def ldapmanager_conn(host)
      @conns ||= {}
      @conns[host] ||= Excon.new("http://#{host}",
                                 proxy: {scheme: 'unix', path: "#{ENV['HOME']}/.stripeproxy"},
                                 persistent: true)
    end

    def user_exists_in_ldapmanager?(host, username)
      resp = ldapmanager_conn(host).get(path: "/api/v1/users/#{username}")

      if resp.status == 200
        true
      elsif resp.status == 400
        false
      else
        raise "Unexpected status from ldapmanager:\n#{resp.inspect}"
      end
    end

    def get_user_from_ldapmanager(host, username)
      resp = ldapmanager_conn(host).get(path: "/api/v1/users/#{username}")
      raise "user should exist in prod:\n#{resp.inspect}" if resp.status != 200

      JSON.load(resp.body)
    end
  end
end
