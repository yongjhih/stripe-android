require 'sixword'
require 'mail'

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
        env = ENV.to_hash
        path = env['PATH'].split(':').delete_if {|d| d.start_with?(File.expand_path('~/.rbenv/versions'))}.join(':')
        env['PATH'] = path
        env
      end

      def init_steps
        step 'write sentinel file' do
          idempotent

          run do
            mgr.ssh_root.file_write('/etc/stripe/yoyo/credentials.generate', 'yes')
          end
        end

        step 'read GPG fingerprint' do
          idempotent

          run do
            log.info <<-EOM
Seems like Marionetting worked! Congrats! Now, on the target machine, run:

     /usr/local/stripe/bin/generate-stripe-keys [stripe-username]@stripe.com

And wait for it to print the words of six. Then, enter them here:
EOM
            fingerprint = ""
            while fingerprint.length < 40
              fingerprint += "%08x" % Sixword::Lib.decode_6_words($stdin.readline.split(' '), true)
            end
            raise "Fingerprint doesn't look right" unless fingerprint.length == 40
            set_fingerprint(fingerprint)
          end
        end

        step 'gpg-sign their key' do
          complete? do
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
            !Dir.glob(File.expand_path("stripe.vpn/#{stripe_email.local}-[0-9]*.tar.gz.gpg", dot_stripe)).empty?
          end

          run do
            Bundler.with_clean_env do
              Subprocess.check_call(%W{./stripe.vpn/add_certs.sh #{stripe_email.local} #{stripe_email.name}},
                                    :cwd => dot_stripe, :env => useful_env)
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
            all_certs = Dir.glob(File.expand_path("stripe.vpn/#{stripe_email.local}-[0-9]*.tar.gz.gpg", dot_stripe))
            latest_cert = all_certs.sort_by { |filename|
              File.stat(filename).mtime
            }.last

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
      end
    end
  end
end
