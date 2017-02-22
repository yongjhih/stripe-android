require 'sixword'
require 'mail'
require 'octokit'
require 'excon'
require 'json'

# I debug things:
require 'pry'

module Yoyo;
  module Steps
    class GenerateCredentials < Yoyo::StepList
      include DotStripeMixin
      include MinitrueMixin

      LDAPMANAGER_HOSTS = ['ldapmanager.corp.stripe.com', 'ldapmanager.qa.corp.stripe.com']

      def set_ssh_key(ssh_key)
        @ssh_key = ssh_key
      end

      def set_client_certificate(cert)
        @client_certificate = cert
      end

      attr_reader :ssh_key
      attr_reader :client_certificate

      def gpg_fingerprint
        output = mgr.ssh.check_output!(%W{gpg --list-secret-keys --no-tty --with-colons --fingerprint <#{stripe_email.address}>})
        output.split("\n").each do |line|
          abbrev, rest = line.split(':', 2)
          if abbrev == 'fpr'
            # fingerprint is in field 10; starting to count at 0, and
            # having stripped away the abbrev, this is index 8:
            return rest.split(':')[8]
          end
        end
        nil
      end

      def stripe_email
        @email ||=
          begin
            stripe_user = mgr.stripe_username || mgr.username
            full_name = mgr.ssh.check_output!(%W{dscl . read /Users/#{mgr.username} RealName}).split("\n")[1]
            Mail::Address.new("\"#{full_name}\" <#{stripe_user}@stripe.com>")
          end
      end

      def fingerprint_equivalent_to_key?(keyid)
        output = Subprocess.check_output(%W{gpg --fingerprint --fingerprint --with-colons #{keyid}})
        !output.scan(/^fpr:+:#{fingerprint.upcase}:$/).empty?
      rescue Subprocess::NonZeroExit
        return false
      end

      def github_client
        @client ||=
          begin
            secret = YAML.load_file(File.expand_path('~/.stripe/github/yoyo.yaml'))
            Octokit::Client.new(:access_token => secret['auth_token'])
          end
      end

      def proxy_conn(host)
        @conns ||= {}
        @conns[host] ||= Excon.new("http://#{host}",
                                   proxy: {scheme: 'unix', path: "#{ENV['HOME']}/.stripeproxy"},
                                   persistent: true)
      end

      def user_exists_in_ldapmanager?(host)
        resp = proxy_conn(host).get(path: "/api/v1/users/#{stripe_email.local}")

        if resp.status == 200
          true
        elsif resp.status == 400
          false
        else
          raise "Unexpected status from ldapmanager:\n#{resp.inspect}"
        end
      end

      # Strip the final comment from the ssh key (this is how the
      # github API stores/returns it)
      def ssh_key_bare
        ssh_key.chomp.split(/\s+/)[0..1].join(' ')
      end

      def init_steps
        step 'write initial puppet facts for cert generation' do
          complete? do
            mgr.ssh_root.if_call!(%w{test -f /etc/stripe/yoyo/keys_generated})
          end

          run do
            mgr.ssh_root.file_write('/etc/stripe/facts/generate_keys.txt', 'yes')
          end
        end

        step 'write initial puppet facts for github cloning' do
          complete? do
            mgr.ssh_root.if_call!(%w{test -f /etc/stripe/yoyo/repos_cloned})
          end

          run do
            mgr.ssh_root.file_write('/etc/stripe/facts/clone_github_repos.txt', 'yes')
          end
        end

        step 'write ssh-initing sentinel file' do
          complete? do
            mgr.ssh_root.if_call!(%w{test -f /etc/stripe/yoyo/ssh.initialized}) &&
              !mgr.ssh_root.if_call!(%w{test -f /etc/stripe/facts/initialize_ssh.txt})
          end

          run do
            mgr.ssh_root.file_write('/etc/stripe/facts/initialize_ssh.txt', "done")
          end
        end

        step 'write re-puppeting sentinel file' do
          idempotent

          run do
            mgr.ssh_root.file_write('/etc/stripe/yoyo/rerun_puppet', 'yes')
          end
        end

        step 'Ask to copy GPG across (for existing stripes)' do
          complete? do
            ! mgr.gpg_key
          end

          run do
            key = mgr.gpg_key.gsub(/\s+/, '').downcase
            unless key.length == 40
              raise "The GPG fingerprint you gave on the commandline (#{mgr.gpg_key}) does not look like a valid GPG fingerprint!"
            end

            log.info <<-EOM

Marionetting complete. Now copy the Stripe's existing GPG key over
to the new machine.

Its fingerprint is #{mgr.gpg_key} (normalized: #{key})

I'll wait...
EOM
            until mgr.ssh.if_call! %W{/usr/local/bin/gpg --list-secret-keys #{key}}, :quiet => true
              sleep 10
            end
          end
        end

        step 'read GPG fingerprint' do
          complete? do
            mgr.gpg_key
          end

          run do
            mgr.update_gpg_key(gpg_fingerprint)
          end
        end

        step 'fetch stripe GPG keys' do
          idempotent

          run do
            Bundler.with_clean_env do
              Subprocess.check_call(%w{fetch-stripe-gpg-keys}, :env => useful_env)
            end
          end
        end

        step 'Wait for generated certificate' do
          idempotent

          run do
            until mgr.ssh.if_call! %W{test -f .stripe-certs/spinup/openssl_selfsigned.pem}
              sleep 10
            end
          end
        end

        step 'Copy VPN shared secrets and certs over' do
          complete? do
            mgr.ssh.if_call! %W{test -f .stripe-certs/spinup/ta.key -a -f .stripe-certs/spinup/ca.crt}
          end

          run do
            Bundler.with_clean_env do
              ta = Subprocess.check_output(%w{fetch-password -q credentialing/vpn/ta-key})
              crt = Subprocess.check_output(%w{fetch-password -q credentialing/vpn/ca-cert})
              mgr.ssh.file_write('.stripe-certs/spinup/ta.key', ta)
              mgr.ssh.file_write('.stripe-certs/spinup/ca.crt', crt)
            end
          end
        end

        step 'Read generated certificate' do
          idempotent

          run do
            if mgr.ssh.if_call! %w{test -f .stripe-certs/spinup/openssl_cert.pem}
              set_client_certificate(mgr.ssh.file_read(".stripe-certs/spinup/openssl_cert.pem"))
            else
              set_client_certificate(mgr.ssh.file_read(".stripe-certs/spinup/openssl_selfsigned.pem"))
            end
          end
        end

        step 'Issue certificate and copy it over' do
          complete? do
            cert = OpenSSL::X509::Certificate.new(client_certificate)
            cert.issuer != cert.subject
          end

          run do
            # Wait for the credentialing user to insert their security key:
            unless gpg_smartcard_ready?
              log.error("I can't yet access your yubikey / smartcard. Please insert it into this computer. I'll wait.")
              until gpg_smartcard_ready?
                sleep 2
              end
            end
            # Now issue it:
            Tempfile.create('client-cert') do |cert|
              cert.write(client_certificate)
              cert.flush
              Subprocess.check_call(%W{minitrue sign --issuer=people --server https://stripe-ca.com --gpg-scd --client-cert #{minitrue_admin_cert} --x509 #{cert.path}})
              mgr.ssh.file_write(".stripe-certs/spinup/openssl_cert.pem", File.read(cert.path))
            end
          end
        end

        step 'Wait for SSH key' do
          idempotent

          run do
            until mgr.ssh.if_call! %W{test -f .ssh/id_rsa_#{stripe_email.address}.pub}
              sleep 10
            end
          end
        end

        step 'Read SSH key' do
          idempotent

          run do
            set_ssh_key(mgr.ssh.file_read(".ssh/id_rsa_#{stripe_email.address}.pub").chomp)
          end
        end

        step 'Add SSH key to github' do
          complete? do
            keys = github_client.keys
            keys.find { |key_entry| key_entry['key'] == ssh_key_bare }
          end

          run do
            github_client.add_key(stripe_email.local, ssh_key)
          end
        end

        step 'Kick off cloning github repos' do
          idempotent

          run do
            mgr.ssh_root.file_write('/etc/stripe/yoyo/github.initialized', "yes\n")
          end
        end

        step 'Wait for clone to finish' do
          complete? do
            mgr.ssh.if_call! %w{test -f /etc/stripe/yoyo/github.cloned}
          end

          run do
            until mgr.ssh.if_call! %w{test -f /etc/stripe/yoyo/github.cloned}
              sleep 30
            end
          end
        end

        step 'Initialize initialize-ssh on the target machine' do
          complete? do
            mgr.ssh.if_call! %w{test -f /etc/stripe/yoyo/ssh.initialized}
          end

          run do
            log.info "Waiting until SSH is initialized..."
            until mgr.ssh.if_call! %w{test -f /etc/stripe/yoyo/ssh.initialized}
              sleep 5
              log.info("Waiting a while longer for SSH to be initialized...")
            end
          end
        end

        step 'Remove SSH key from github' do
          idempotent

          run do
            the_key = github_client.keys.find { |key| key['key'] == ssh_key_bare }
            github_client.remove_key(the_key['id']) if the_key
          end
        end

        step 'Register user with hackpad' do
          idempotent

          run do
            hp = SpaceCommander::Server.new('hackpad1.northwest.stripe.io')
            hp.ssh_cmd_check_call %W{sudo hackpad-mkuser #{stripe_email.name} #{stripe_email.local}}
          end
        end

        step "Add new user to LDAP using ldapmanager (prod)" do
          host = 'ldapmanager.corp.stripe.com'
          complete? do
            user_exists_in_ldapmanager?(host)
          end

          run do
            create_request = {
              username: stripe_email.local,
              name: stripe_email.name,

              groups: mgr.puppet_groups,
              pubkeys: [],
            }
            resp = proxy_conn(host).post(path: '/api/v1/users', body: JSON.dump(create_request))
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
            resp = proxy_conn(prod_host).get(path: "/api/v1/users/#{stripe_email.local}")
            raise "user should exist in prod:\n#{resp.inspect}" if resp.status != 200

            unix_uid = JSON.load(resp.body)['uid']
            raise "invalid uid: #{unix_uid.inspect}" unless unix_uid.is_a?(Integer)

            create_request = {
              username: stripe_email.local,
              name: stripe_email.name,
              uid: unix_uid,

              groups: mgr.puppet_groups,
              pubkeys: [],
            }
            resp = proxy_conn(host).post(path: '/api/v1/users', body: JSON.dump(create_request))
            raise "error creating user:\n#{resp.inspect}" if resp.status != 200
          end
        end

        LDAPMANAGER_HOSTS.each do |host|
          step "Add SSH key to LDAP using ldapmanager (host: #{host})" do
            complete? do
              resp = proxy_conn(host).get(path: "/api/v1/users/#{stripe_email.local}")

              # We must have the user, since it gets created above.
              raise "User not found in ldapmanager" unless resp.status == 200

              user_info = JSON.load(resp.body)
              user_info['public_keys'].include?(ssh_key)
            end

            run do
              body = {public_key: ssh_key}
              resp = proxy_conn(host).post(path: "/api/v1/users/#{stripe_email.local}/ssh_keys", body: JSON.dump(body))

              # Note: this returns a 204 No Content
              raise "error adding SSH key:\n#{resp.inspect}" if resp.status != 204
            end
          end
        end
      end
    end
  end
end
