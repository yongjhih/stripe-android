module Yoyo
  module Steps
    class GPGRevoke < Yoyo::Steps::AbstractGPGSigningSteps
      def set_passphrase(name, value)
        @passphrases ||= {}
        @passphrases[name] = value
      end

      def get_passphrase(name)
        @passphrases.fetch(name)
      end

      def each_passhprase(&block)
        @passphrases.each(&block)
      end

      def run!
        if mgr.gpg_key.nil?
          log.info "No GPG key to revoke, so nothing to do"
          return
        end
        super
      end

      def init_gpg_steps
        step 'Retrieve passwords for the identities' do
          idempotent

          run do

            mgr.gpg_signing_identities.each do |identity|
              set_passphrase(identity, Subprocess.check_output(%W{fetch-password gnupg/#{identity}/passphrase},
                                                               env: useful_env).chomp)
            end
          end
        end

        step 'Revoke the CA signature with gpg' do
          complete? do
            revokers = Subprocess.check_output(gpg(%W{--list-keys --with-colons #{mgr.gpg_key}}), cwd: ramdisk_path).split("\n").grep(/\Arkv:/)

            # Can't automatically revoke with any other CA at the
            # moment, or keys that don't have the CA identity as a
            # designated revoker:
            !mgr.gpg_signing_identities.include?('ca') ||
              !revokers.find { |revoker| revoker.split(':')[6] != signing_identities['ca'] }
          end

          run do
            passphrase = get_passphrase('ca')
            pp_in, pp_out = IO.pipe
            gpg = Subprocess.popen(gpg(%W{--passphrase-fd #{pp_in.fileno}
                                            --desig-revoke #{mgr.gpg_key}}),
                                   cwd: ramdisk_path, retain_fds: [pp_in],
                                   stdout: Subprocess::PIPE)
            pp_in.close
            pp_out.write(passphrase)
            pp_out.close
            revcert, _ = gpg.communicate
            raise "Could not revoke." unless gpg.wait.success?

            import = Subprocess.popen(gpg(%W{--import}), cwd: ramdisk_path, stdin: Subprocess::PIPE)
            import.communicate(revcert)
            raise "Could not import revocation cert." unless import.wait.success?
          end
        end

        step 'Edit the key interactively because GPG automation sucks' do
          idempotent
          run do
            puts <<EOM
We will now have to revoke the signature on each UID manually - this
sucks, and I'm very sorry.

You will need these passphrases:

EOM
            each_passhprase do |name, passphrase|
              puts "#{name}:\t\t#{passphrase}"
            end
            puts <<EOM
Type "revsig" and answer the prompts. Then, type "save".
EOM
            Subprocess.check_call(gpg(%W{--edit-key #{mgr.gpg_key}}), cwd: ramdisk_path)
          end
        end

        step 'Confirm revocation' do
          complete? do
            mgr.gpg_key.length == 40
          end

          run do
            Subprocess.check_call(gpg(%W{--list-sigs #{mgr.gpg_key}}), cwd: ramdisk_path)
            $stdout.write "Does this look sane? Enter 'revoke' and I will push to keyservers: "
            $stdout.flush
            if 'revoke' != $stdin.readline.chomp
              raise "Not confirmed - aborting."
            end
          end
        end
      end
    end
  end
end
