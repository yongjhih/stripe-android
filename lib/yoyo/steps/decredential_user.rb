require File.expand_path("~/stripe/vpnmaker/vpnmaker")
require 'csv'
require 'openssl'

module Yoyo
  module Steps
    # Steps to disable the most critical of a user's accesses. This is
    # not complete, see
    # https://hackpad.stripe.com/Decredentialing-Checklist-Template-QbLT18NFYkP
    # for the actual steps to perform. However, it is intended to be
    # useful to clear the list of critical things as quickly as
    # possible.
    class DecredentialUser < Yoyo::StepList
      include DotStripeMixin

      def vpnmaker
        @vpnmaker ||= VPNMaker::Manager.new(File.expand_path("~/.stripe/stripe.vpn/"))
      end

      def contractor_ca_index
        CSV.parse(File.open(File.expand_path('~/.stripe/ca/data/index.txt')), col_sep: "\t")
      end

      def unrevoked_contractor_serials(username)
        index = contractor_ca_index
        entries_for_user = index.select do |entry|
          puts entry
          if dn = OpenSSL::X509::Name.parse(entry[5])
            dn.to_a.find { |component| component[0] == 'CN' && component[1] == username}
          end
        end
        entries_for_user.select { |entry| entry[0] != 'R' }.map { |entry| entry[3] }
      end

      def init_steps
        %w{stripe.io apiori.com}.each do |domain|
          step "revoke AWS credentials for #{domain}" do
            complete? do
              begin
                users = Subprocess.check_output(%W{sc-iam list-users #{domain}}, :env => useful_env).split("\n")
                !users.include?(mgr.username)
              rescue Subprocess::NonZeroExit
                # Don't break now, but warn profusely:
                log.error "Could not check if #{domain} has keys for #{mgr.username}. Do you have creds?"
                log.warning "Blazing ahead anyway..."
                true
              end
            end

            run do
              Subprocess.check_call(%W{sc-iam delete-user #{domain} #{mgr.username}}, :env => useful_env)
            end
          end
        end

        step 'update .stripe' do
          idempotent

          run do
            Subprocess.check_call(%w{./bin/dot-git pull}, :cwd => dot_stripe, :env => useful_env)
            raise "It appears your ~/.stripe directory is dirty - please clean it up!" unless dot_stripe_clean?
          end
        end

        step 'revoke VPN certificates for a full-time stripe' do
          complete? do
            # This user is not known as a fulltime person:
            return true if (user = vpnmaker.tracker.users[mgr.username]).nil?

            version = vpnmaker.tracker.active_key_version
            while version >= 0
              return false unless vpnmaker.tracker.revoked?(mgr.username, version)
              version -= 1
            end
            true
          end

          run do
            Subprocess.check_call(%W{./stripe.vpn/revoke-certs #{mgr.username}}, :cwd => dot_stripe, :env => useful_env)
          end
        end

        step 'revoke VPN certificates for a contractor' do
          complete? do
            unrevoked_contractor_serials(mgr.username).empty?
          end

          run do
            unrevoked_contractor_serials(mgr.username).each do |serial|
              Subprocess.check_call(%W{bash -c '. vars && ./scripts/revoke data/#{serial}.pem'},
                                    :cwd => File.join(dot_stripe, 'ca'),
                                    :env => useful_env)
            end
          end
        end

        commit_and_push_dot_stripe_steps { "Decredential #{mgr.username}" }
      end
    end
  end
end
