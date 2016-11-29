module Yoyo
  module Steps
    class AbstractGPGSigningSteps < Yoyo::StepList
      def init_gpg_steps
        raise "Please implement init_gpg_steps"
      end

      def gpg(args)
        %W{gpg --no-options --no-default-keyring
           --keyring ./pubring.gpg
           --secret-keyring ./secring.gpg
           --trustdb-name ./trustdb.gpg
           } + args
      end

      attr_reader :keyservers, :ramdisk_path
      def set_ramdisk_path(path)
        @ramdisk_path = path.chomp
      end

      def set_keyservers(keyservers)
        @keyservers = keyservers
      end

      def signing_identities
        @signing_identities ||= {}
      end

      def useful_env
        Bundler.with_clean_env do
          env = ENV.to_hash
          rbenv_root = ENV['RBENV_ROOT'] || File.expand_path('~/.rbenv')
          path = env['PATH'].split(':').delete_if {|d| d.start_with?(File.join(rbenv_root, 'versions'))}.join(':')
          env['PATH'] = path
          env.delete('RBENV_VERSION')
          env
        end
      end

      def destroy_ramdisk
        Subprocess.check_call(%W{#{mgr.utility_binary('ramdisk')} destroy #{mgr.gpg_ramdisk_name}})
        log.info "Ramdisk #{mgr.gpg_ramdisk_name} was successfully destroyed."
      end

      def run!
        ok = false
        begin
          super
          ok = true
        ensure
          unless ok
            log.error("Oh no, something went wrong, destroying the ramdisk!")
          end
          destroy_ramdisk
        end
      end

      def init_steps
        step 'Set up ramdisk for our secrets' do
          complete? do
            begin
              set_ramdisk_path(Subprocess.check_output(%W{#{mgr.utility_binary('ramdisk')} path #{mgr.gpg_ramdisk_name}}))
              true
            rescue Subprocess::NonZeroExit
              false
            end
          end

          run do
            Subprocess.check_call(%W{#{mgr.utility_binary('ramdisk')} create #{mgr.gpg_ramdisk_name}})
            set_ramdisk_path(Subprocess.check_output(%W{#{mgr.utility_binary('ramdisk')} path #{mgr.gpg_ramdisk_name}}))
          end
        end

        step 'Load signing identities' do
          idempotent

          run do
            Bundler.with_clean_env do
              mgr.gpg_signing_identities.each do |identity|
                signing_identities[identity] = Subprocess.check_output(%W{fetch-password gnupg/#{identity}/fingerprint},
                                                                       env: useful_env).chomp
              end
            end
          end
        end

        step 'Load keyservers' do
          idempotent
          run do
            Bundler.with_clean_env do
              set_keyservers(Subprocess.check_output(%W{ls-servers --silent -NSat keyserver},
                                                     env: useful_env).split("\n"))
            end
          end
        end

        step 'Set up GPG inside ramdisk' do
          complete? do
            catch :returning do
              mgr.gpg_signing_identities.each do |identity|
                fpr = signing_identities[identity]
                begin
                  log.info "Checking for #{fpr}:"
                  Subprocess.check_call(gpg(%W{--list-keys #{fpr}}), cwd: ramdisk_path)
                  Subprocess.check_call(gpg(%W{--list-secret-keys #{fpr}}), cwd: ramdisk_path)
                rescue Subprocess::NonZeroExit
                  throw :returning, false
                end
              end
              true
            end
          end

          run do
            Bundler.with_clean_env do
              mgr.gpg_signing_identities.each do |identity|
                pubkey = Subprocess.check_output(%W{fetch-password gnupg/#{identity}/pubkey}, env: useful_env)
                privkey = Subprocess.check_output(%W{fetch-password gnupg/#{identity}/privkey}, env: useful_env)
                gpg_command = gpg(%W{--import})
                import = Subprocess.popen(gpg_command, cwd: ramdisk_path, stdin: Subprocess::PIPE)
                import.communicate(pubkey + privkey)
                raise 'Could not import key' unless import.wait.success?
              end
            end
          end
        end

        step 'Retrieve the identity to sign' do
          complete? do
            begin
              Subprocess.check_call(gpg(%W{--list-keys #{mgr.gpg_key}}), cwd: ramdisk_path)
              true
            rescue Subprocess::NonZeroExit
              false
            end
          end

          run do
            succeeded = false
            keyservers.each do |ks|
              begin
                Bundler.with_clean_env do
                  Subprocess.check_call(gpg(%W{--keyserver #{ks} --recv-key #{mgr.gpg_key}}),
                                        cwd: ramdisk_path)
                end
                succeeded = true
              rescue Subprocess::NonZeroExit
              end
            end
            raise "Couldn't retrieve #{mgr.gpg_key} from any keyservers" unless succeeded
          end
        end

        init_gpg_steps

        step 'Send to keyservers' do
          idempotent
          run do
            keyservers.each do |ks|
              Subprocess.check_call(gpg(%W{--keyserver #{ks} --send-key #{mgr.gpg_key}}), cwd: ramdisk_path)
            end
          end
        end
      end
    end
  end
end
