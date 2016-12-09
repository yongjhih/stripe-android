require File.expand_path("~/.stripe/stripe.vpn/vpnmaker/vpnmaker")
require 'csv'
require 'openssl'

module Yoyo
  module Steps
    # Steps to disable the most critical of a user's accesses. This is
    # not complete, see
    # https://hackpad.corp.stripe.com/Decredentialing-Checklist-Template-QbLT18NFYkP
    # for the actual steps to perform. However, it is intended to be
    # useful to clear the list of critical things as quickly as
    # possible.
    class DecredentialUser < Yoyo::StepList
      include DotStripeMixin
      include MinitrueMixin

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
        step 'Determine GPG fingerprint (if any)' do
          idempotent

          run do
            Subprocess.check_call(%W{fetch-stripe-gpg-keys}, env: useful_env)
            output = Subprocess.check_output(%W{gpg --with-colons --list-keys --fingerprint #{mgr.username}})
            fpr = nil
            stripe_uid_valid = false
            output.each_line do |line|
              components = line.split(':')
              case components[0]
              when 'fpr'
                if stripe_uid_valid
                  fpr = components[9]
                  break
                end
              when 'uid', 'pub', 'sub'
                if components[1] != 'u' # 'r' means revoked
                  fpr = nil
                  stripe_uid_valid = false
                  next
                else
                  if components[0] == 'uid'
                    email = Mail::Address.new(components[9])
                    if email.domain == 'stripe.com' && email.local == mgr.username
                      stripe_uid_valid = true
                      next
                    end
                  end
                end
              end
            end
            if fpr && stripe_uid_valid
              mgr.gpg_key = fpr
            end
          end
        end

        %w{stripe.io apiori.com}.each do |domain|
          step "revoke AWS credentials for #{domain}" do
            complete? do
              begin
                users = Subprocess.check_output(%W{sc-iam list-users #{domain}}, :env => useful_env).split("\n")
                !users.include?(mgr.username)
              rescue Subprocess::NonZeroExit
                # Don't break now, but warn profusely:
                log.error "Could not check if #{domain} has keys for #{mgr.username}. Do you have creds?"
                log.warn "Blazing ahead anyway..."
                true
              end
            end

            run do
              Subprocess.check_call(%W{sc-iam delete-user #{domain} #{mgr.username}}, :env => useful_env)
            end
          end
        end

        step 'Revoke minitrue certs on all regions' do
          idempotent

          run do
            unless gpg_smartcard_ready?
              log.error("I can't yet access your yubikey / smartcard. Please insert it into this computer. I'll wait.")
              until gpg_smartcard_ready?
                sleep 2
              end
            end

            MINITRUE_REGIONS.each do |region|
              url = "https://#{region}.stripe-ca.com/"
              # TODO: Once we can specify a serial nunmber (for
              # theft-revocation purposes), we should limit ourselves
              # only to those serial numbers. Right now, that's not
              # possible though.
              Subprocess.check_output(%W{minitrue list --server #{url} --client-cert #{minitrue_admin_cert} --gpg-scd --issuer=people --x509 --prefix #{mgr.username}/}).each_line do |cert|
                Subprocess.check_call(%W{minitrue revoke --server #{url} --client-cert #{minitrue_admin_cert} --gpg-scd --issuer=people --x509 --name #{cert}},
                                      stdout: nil)
              end
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
            next true if (user = vpnmaker.tracker.users[mgr.username]).nil?

            version = vpnmaker.tracker.active_key_version(mgr.username)
            found = false
            while version >= 0 && !found
              next (found = true) unless vpnmaker.tracker.revoked?(mgr.username, version)
              version -= 1
            end
            !found
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
              Subprocess.check_call(%W{bash -c} + [". vars && ./scripts/revoke data/#{serial}.pem"],
                                    :cwd => File.join(dot_stripe, 'ca'),
                                    :env => useful_env)
            end
          end
        end

        commit_and_push_dot_stripe_steps { "Decredential #{mgr.username}" }

        step 'Update VPN and intfe CRLs' do
          idempotent

          run do
            Subprocess.check_call(%w{bin/upload-stripe-vpn}, :cwd => dot_stripe, :env => useful_env)
            %w{mainland qa}.each do |island|
              Subprocess.check_call(%W{sc-puppet-secrets #{island} },
                                    :env => useful_env)
            end
            Subprocess.check_call(%w{for-servers -Sayt vpn -t intfe stripe-puppet}, :env => useful_env)
          end
        end
      end
    end
  end
end
