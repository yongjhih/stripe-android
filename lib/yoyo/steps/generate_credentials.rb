require 'sixword'
require 'mail'
require 'octokit'

# I debug things:
require 'pry'

module Yoyo;
  module Steps
    class GenerateCredentials < Yoyo::StepList
      def dot_stripe
        File.expand_path("~/.stripe")
      end

      def set_fingerprint(fpr)
        @fingerprint = fpr
      end

      def gpg_long_keyid
        fingerprint[24..-1]
      end

      def set_ssh_key(ssh_key)
        @ssh_key = ssh_key
      end

      attr_reader :ssh_key
      attr_reader :fingerprint

      def stripe_email
        @key_parse_done ||=
          begin
            Subprocess.check_call(%W{gpg --no-tty --with-colons --list-key #{fingerprint}},
                                  :stdout => Subprocess::PIPE,
                                  :stdin => nil) do |process|
              output, err = process.communicate
              uids = []
              output.each_line do |line|
                abbrev, rest = line.chomp.split(':', 2)
                if %w[uid pub].include?(abbrev)
                  uids << Mail::Address.new(rest.split(':')[8])
                end
              end
              log.debug("Found UIDs on key: #{uids}")
              @stripe_email = uids.find { |addr| addr.domain == 'stripe.com' }
              log.debug("Found @stripe.com UID #{@stripe_email}")
            end
            true
          end
        @stripe_email
      end

      def git_dir_clean?(dir)
        # Any staged but uncommitted changes? Exit status 1 = yep.
        Subprocess.call(%w{git diff-index --quiet HEAD}, :cwd => dir).success? &&
          # Any unstaged changes? Exit status 1 = yep.
          Subprocess.call(%w{git diff-files --quiet}, :cwd => dir).success?
      end

      def dot_stripe_clean?
        git_dir_clean?(dot_stripe)
      end

      def puppet_auth_config
        File.expand_path('~/stripe/puppet-config/yaml/auth.yaml')
      end

      def puppet_users_list
        YAML.load_file(puppet_auth_config)
      end

      def useful_env
        Bundler.with_clean_env do
          env = ENV.to_hash
          path = env['PATH'].split(':').delete_if {|d| d.start_with?(File.expand_path('~/.rbenv/versions'))}.join(':')
          env['PATH'] = path
          env
        end
      end

      def latest_cert
        all_certs = Dir.glob(File.expand_path("stripe.vpn/#{stripe_email.local}-[0-9]*.tar.gz.gpg", dot_stripe))
        all_certs.sort_by { |filename|
          File.stat(filename).mtime
        }.last
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
            Octokit::Client.new(:oauth_token => secret['auth_token'])
          end
      end

      # Strip the final comment from the ssh key (this is how the
      # github API stores/returns it)
      def ssh_key_bare
        ssh_key.chomp.split(/\s+/)[0..1].join(' ')
      end

      def init_steps
        step 'write sentinel file' do
          idempotent

          run do
            mgr.ssh_root.file_write('/etc/stripe/yoyo/credentials.generate', 'yes')
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
            set_fingerprint(key)
          end
        end

        step 'read GPG fingerprint' do
          complete? do
            fingerprint
          end

          run do
            log.info <<-EOM
Seems like Marionetting worked! Congrats! The target machine will now
generate a GPG and SSH key.

Please enter the words of six here:
EOM
            fingerprint = ""
            while fingerprint.length < 40
              begin
                fingerprint += "%08x" % Sixword::Lib.decode_6_words($stdin.readline.split(' '), true)
              rescue ArgumentError => e
                log.error "That was not a valid sixwords line (#{e.to_s}). Retry!"
              end
            end
            raise "Fingerprint doesn't look right" unless fingerprint.length == 40
            set_fingerprint(fingerprint)
          end
        end

        step 'gpg-sign their key' do
          complete? do
            mgr.gpg_key ||
              Subprocess.call(%W{./gnupg/is_key_signed.sh #{fingerprint}}, :cwd => dot_stripe, :env => useful_env).success?
          end

          run do
            raise "~/.stripe has uncommitted stuff in it! Clean it up, please!" unless dot_stripe_clean?
            Subprocess.check_call(%w{./bin/dot-git pull}, :cwd => dot_stripe, :env => useful_env)

            space_commander = File.expand_path("~/stripe/space-commander/bin")
            Bundler.with_clean_env do
              path = ENV['PATH'].split(':').delete_if {|d| d.start_with?(File.expand_path('~/.rbenv/versions'))}.join(':')
              Subprocess.check_call(%W{bash -x ./gnupg/sign_gpg_key_with_ca.sh #{fingerprint}},
                                    :cwd => dot_stripe,
                                    :env => useful_env)
            end
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

        step 'generate VPN certs' do
          complete? do
            if latest_cert
              output = Subprocess.check_output(['gpg', '--no-default-keyring', '--keyring', '/dev/null',
                                                '--secret-keyring', '/dev/null', '--list-only', '--list-packets',
                                                '--verbose', latest_cert])

              output.scan(/^:pubkey enc packet: .* keyid (.+)$/).flatten.find { |keyid| fingerprint_equivalent_to_key?(keyid) }
            end
          end

          run do
            Bundler.with_clean_env do
              cmdline = %w{./stripe.vpn/add_certs.sh}
              cmdline += %w{-a} if mgr.gpg_key # default to not revoking vpn certs for a second machine
              cmdline += %W{-k #{fingerprint}}
              cmdline += [stripe_email.local, stripe_email.name]
              Subprocess.check_call(cmdline, :cwd => dot_stripe, :env => useful_env)
            end
          end
        end

        step 'commit ~/.stripe' do
          complete? do
            dot_stripe_clean?
          end

          run do
            log.debug("Adding files...")
            Subprocess.check_call(%w{git add .}, :cwd => dot_stripe)
            log.debug("Added files...")
            message = "Provision #{stripe_email.to_s} with GPG fingerprint #{fingerprint}"
            Subprocess.check_call(%W{git commit -m #{message}}, :cwd => dot_stripe)
          end
        end

        step 'push ~/.stripe' do
          idempotent

          run do
            Subprocess.check_call(%w{bin/dot-git push}, :cwd => dot_stripe)
          end
        end

        step 'copy VPN certs to machine' do
          idempotent

          run do
            log.debug("Latest cert file we have for this stripe is #{latest_cert}")

            mgr.ssh.file_write(File.join('Desktop', 'certs.tar.gz.gpg'), File.read(latest_cert))
            log.info("Now you can run /usr/local/stripe/bin/import-vpn-certs ~/Desktop/certs.tar.gz.gpg")
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

        step 'read GPG-signed SSH key' do
          idempotent

          run do
            verifier = GPGVerifier.new()
            verifier.read_ascii_armor_data
            if stripe_email.to_s != verifier.signature_address.to_s
              raise "The GPG data isn't signed by #{stripe_email.to_s}; " +
                    "it's signed by #{verifier.signature_address.to_s}"
            end
            if fingerprint.upcase != verifier.signature_fpr.upcase
              raise "The GPG data isn't signed by #{fingerprint.upcase}; " +
                    "it's signed by #{verifier.signature_fpr.upcase}"
            end
            set_ssh_key(verifier.data.rstrip)
          end
        end

        step 'add user entry to puppet' do
          complete? do
            users = puppet_users_list
            users.fetch('auth::users').fetch(stripe_email.local, nil)
          end

          run do
            users = puppet_users_list
            users.fetch('auth::users')[stripe_email.local] = {
              name: stripe_email.name,
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

        step 'Clone github repos' do
          complete? do
            mgr.ssh_root.if_call! %w{test -f /etc/stripe/yoyo/repos.initialized}
          end

          run do
            if ! mgr.ssh.if_call! %w{test -x /Volumes/Marionette\ Cache/git/clone-all}, :quiet => true
              log.info "Will now clone github repos."
              log.info "Please insert the Marionette Cache thumbdrive into the target machine."
              until mgr.ssh.if_call! %w{test -x /Volumes/Marionette\ Cache/git/clone-all}, :quiet => true
                sleep 5
              end
            end
            mgr.ssh.check_call! %w{/Volumes/Marionette\ Cache/git/clone-all}
            mgr.ssh_root.file_write('/etc/stripe/yoyo/repos.initialized', "yes\n")
          end
        end

        step 'Add the user to the dot-stripe2 key' do
          complete? do
            output = Subprocess.check_output(%w{fetch-password-recipients -r stripe/dot-stripe2-encfs},
                                              :env => useful_env)
            output.chomp.split(/\s+/).find { |keyid| fingerprint_equivalent_to_key?(keyid) }
          end

          run do
            Subprocess.check_call(%W{add-password-user -r #{gpg_long_keyid} stripe/dot-stripe2-encfs},
                                  :env => useful_env)
          end
        end

        step 'Remove SSH key from github' do
          idempotent

          run do
            the_key = github_client.keys.find { |key| key['key'] == ssh_key_bare }
            github_client.remove_key(the_key['id']) if the_key
          end
        end

        step 'Run initialize-ssh on the target machine' do
          idempotent

          run do
            vault_conn = SpaceCommander::SSH::Connection.new('root', 'vault.stripe.io')
            host_key = vault_conn.file_read('/etc/ssh/ssh_host_rsa_key.pub')

            vault_port = vault_conn.conn.options[:port]
            vault_ip = vault_conn.conn.options[:host_name]
            host_string = "[vault.stripe.io]:#{vault_port},[#{vault_ip}]:#{vault_port} "
            mgr.ssh_root.file_write('/etc/stripe/yoyo/vault_host_key.pub', host_string + host_key)
          end
        end
      end
    end
  end
end
