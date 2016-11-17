require 'sixword'
require 'mail'
require 'octokit'

# I debug things:
require 'pry'

module Yoyo;
  module Steps
    class GenerateCredentials < Yoyo::StepList
      include DotStripeMixin
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

      def gpg_smartcard_ready?
        begin
          Subprocess.check_call(%w{gpg --no-tty --card-status}, cwd: '/', stdout: nil, stderr: nil)
        rescue Subprocess::NonZeroExit
          false
        end
      end

      def stripe_email
        @email ||=
          begin
            stripe_user = mgr.stripe_username || mgr.username
            full_name = mgr.ssh.check_output!(%W{dscl . read /Users/#{mgr.username} RealName}).split("\n")[1]
            Mail::Address.new("\"#{full_name}\" <#{stripe_user}@stripe.com>")
          end
      end

      def puppet_auth_config
        File.expand_path('~/stripe/puppet-config/yaml/auth.yaml')
      end

      def puppet_users_list
        YAML.load_file(puppet_auth_config)
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
            admin_cert = File.expand_path('~/.stripe-ca/admin.crt')
            Tempfile.create('client-cert') do |cert|
              cert.write(client_certificate)
              cert.flush
              Subprocess.check_call(%W{minitrue sign --issuer=people --server https://stripe-ca.com --gpg-scd --client-cert #{admin_cert} --x509 #{cert.path}})
              mgr.ssh.file_write(".stripe-certs/spinup/openssl_cert.pem", File.read(cert.path))
            end
          end
        end

        step 'ensure puppet dir is clean' do
          idempotent

          run do
            puppet_dir = File.expand_path('../', File.dirname(puppet_auth_config))
            unless git_dir_clean?(puppet_dir)
              raise "Puppet directory isn't clean. Please clean it up & re-run yoyo"
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

        step 'add user entry to puppet' do
          complete? do
            users = puppet_users_list
            users.fetch('auth::users').fetch(stripe_email.local, nil)
          end

          run do
            users = puppet_users_list
            max_uid = users.fetch('auth::users').map{|_,v| v.fetch(:uid, 9999)}.max
            users.fetch('auth::users')[stripe_email.local] = {
              name: stripe_email.name,
              uid: max_uid + 1,
              pubkeys: [],
              privileges: mgr.puppet_groups
            }
            File.write(puppet_auth_config, users.to_yaml)
          end
        end

        step 'add SSH key to puppet' do
          complete? do
            users = puppet_users_list['auth::users']
            if user_entry = users.fetch(stripe_email.local)
              user_entry.fetch(:pubkeys).include?(ssh_key)
            end
          end

          run do
            users = puppet_users_list
            users['auth::users'].fetch(stripe_email.local)[:pubkeys] << ssh_key
            File.write(puppet_auth_config, users.to_yaml)
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
            user = SpaceCommander::Utils.get_stripe_username
            hp_conn = SpaceCommander::SSH::Connection.new(user, 'hackpad1.northwest.stripe.io')
            hp_conn.check_call! %W{sudo hackpad-mkuser #{stripe_email.name} #{stripe_email.local}}
          end
        end

        step 'Wait for puppet to be committed' do
          idempotent

          run do
            puppet_dir = File.expand_path('../', File.dirname(puppet_auth_config))
            until git_dir_clean?(puppet_dir)
              log.warn("Puppet directory still has our uncommitted changes in it - please commit and push!")
              sleep 10
            end
          end
        end
      end
    end
  end
end
