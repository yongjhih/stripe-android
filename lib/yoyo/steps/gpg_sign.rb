module Yoyo
  module Steps
    class GPGSign < Yoyo::Steps::AbstractGPGSigningSteps
      def init_gpg_steps
        step 'Verify we have the right key' do
          complete? do
            mgr.gpg_key.length == 40
          end

          run do
            puts "Please check that the key #{mgr.gpg_key} is the right one:"
            Subprocess.check_call(gpg(%W{--fingerprint #{mgr.gpg_key}}), cwd: ramdisk_path)
            $stdout.write("Please type the string 'sign' to sign the key above (you won't be prompted again): ")
            $stdout.flush
            if 'sign' != $stdin.readline.chomp
              raise "Aborted due to input (was not 'sign')."
            end
          end
        end

        step 'Sign the identity with gpg' do
          idempotent
          run do
            mgr.gpg_signing_identities.each do |identity|
              fpr = signing_identities[identity]
              passphrase = Bundler.with_clean_env {Subprocess.check_output(%W{fetch-password gnupg/#{identity}/passphrase}, env: useful_env).chomp}
              pp_in, pp_out = IO.pipe
              gpg = Subprocess.popen(gpg(%W{--default-key #{fpr}
                                            --passphrase-fd #{pp_in.fileno}
                                            --batch --yes
                                            --sign-key #{mgr.gpg_key}}),
                                     cwd: ramdisk_path, retain_fds: [pp_in])
              pp_in.close
              pp_out.write(passphrase)
              pp_out.close
              raise "Could not sign with #{identity}" unless gpg.wait.success?
            end
          end
        end
      end
    end
  end
end
