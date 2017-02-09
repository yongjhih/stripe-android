module Yoyo
  module Steps
    class GPGRevokeAll < Yoyo::StepList
      attr_reader :gpg_keys
      def set_gpg_keys(keys)
        @gpg_keys = keys
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

      def init_steps
        step 'Retrieve keys from the keyservers' do
          idempotent
          run do
            Subprocess.check_call(%w{fetch-stripe-gpg-keys}, env: useful_env)
          end
        end

        step 'Find keys matching the username' do
          idempotent
          run do
            keys = []
            process_fpr = false
            Subprocess.check_output(%W{gpg --list-keys --fingerprint --with-colons <#{mgr.username}@stripe.com>},
                                           env: useful_env).each_line do |line|
              tag, trust, rest = line.split(':', 3)
              if process_fpr && tag == 'fpr'
                fpr = rest.split(':')[-2]
                log.info("Need to revoke #{fpr}")
                keys << fpr
                process_fpr = false
              end
              next unless tag == 'pub' || tag == 'fpr'
              next if trust == 'r' # no need to process this if it's revoked
              process_fpr = true
            end
            set_gpg_keys(keys)
          end
        end

        step 'Revoke all keys found' do
          idempotent
          run do
            gpg_keys.each do |key|
              mgr.gpg_key = key
              mgr.run_steps([
                              Yoyo::Steps::GPGRevoke
                            ])
            end
            mgr.gpg_key = nil
          end
        end

        step 'Retrieve keys from the keyservers again' do
          idempotent
          run do
            Subprocess.check_call(%w{fetch-stripe-gpg-keys}, env: useful_env)
          end
        end
      end
    end
  end
end
