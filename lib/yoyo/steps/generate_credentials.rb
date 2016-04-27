require 'sixword'
require 'mail'
require 'octokit'

# I debug things:
require 'pry'

module Yoyo;
  module Steps
    class GenerateCredentials < Yoyo::StepList
      include DotStripeMixin

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
            set_fingerprint(key)
          end
        end

        step 'read GPG fingerprint' do
          complete? do
            fingerprint
          end

          run do
            log.info <<-EOM
Seems like Marionetting worked! Congrats!


********************************************************************************
******************************* DANGER! ****************************************
********************************************************************************

                             .ed"""" """$$$$be.
                           -"           ^""**$$$e.
                         ."                   '$$$c
                        /                      "4$$b
                       d  3                      $$$$
                       $  *                   .$$$$$$
                      .$  ^c           $$$$$e$$$$$$$$.
                      d$L  4.         4$$$$$$$$$$$$$$b
                      $$$$b ^ceeeee.  4$$ECL.F*$$$$$$$
          e$""=.      $$$$P d$$$$F $ $$$$$$$$$- $$$$$$
         z$$b. ^c     3$$$F "$$$$b   $"$$$$$$$  $$$$*"      .=""$c
        4$$$$L        $$P"  "$$b   .$ $$$$$...e$$        .=  e$$$.
        ^*$$$$$c  %..   *c    ..    $$ 3$$$$$$$$$$eF     zP  d$$$$$
          "**$$$ec   "   %ce""    $$$  $$$$$$$$$$*    .r" =$$$$P""
                "*$b.  "c  *$e.    *** d$$$$$"L$$    .d"  e$$***"
                  ^*$$c ^$c $$$      4J$$$$$% $$$ .e*".eeP"
                     "$$$$$$"'$=e....$*$$**$cz$$" "..d$*"
                       "*$$$  *=%4.$ L L$ P3$$$F $$$P"
                          "$   "%*ebJLzb$e$$$$$b $P"
                            %..      4$$$$$$$$$$ "
                             $$$e   z$$$$$$$$$$%
                              "*$c  "$$$$$$$P"
                               ."""*$$$$$$$$bc
                            .-"    .$***$$$"""*e.
                         .-"    .e$"     "*$c  ^*b.
                  .=*""""    .e$*"          "*bc  "*$e..
                .$"        .z*"               ^*$e.   "*****e.
                $$ee$c   .d"                     "*$.        3.
                ^*$E")$..$"                         *   .ee==d%
                   $.d$$$*                           *  J$$$e*
                    """""                              "$$$"


NOW'S A GREAT TIME TO CHECK IN WITH ANYONE ELSE WHO MAY BE CREDENTIALING.
FROM THE MOMENT YOU ENTER THE GPG WORDS OF SIX, UNTIL YOU COMMIT YOUR CHANGES
FOR THIS USER TO PUPPET-CONFIG, THERE IS POTENTIAL FOR GIT CONFLICT SADNESS.

IF SOMEONE ELSE IS CREDENTIALING, ASK THEM TO WAIT FOR YOU TO DO THIS
(AND COMMIT YOUR PUPPET CHANGES) OR WAIT UNTIL THEY'VE DONE THE SAME.

********************************************************************************
********************************************************************************

The target machine will now generate a GPG and SSH key.

Please enter the words of six here:
EOM
            fingerprint = ""
            while fingerprint.length < 40
              begin
                line = $stdin.readline
                fingerprint += Sixword::Hex.encode(Sixword.pad_decode(line))
              rescue Sixword::InputError => e
                log.error "That was not a valid sixwords line (#{line} -- #{e.to_s}). Retry!"
              end
            end
            raise "Fingerprint doesn't look right" unless fingerprint.length == 40
            set_fingerprint(fingerprint)
          end
        end

        step 'update ~/.stripe' do
          idempotent

          run do
            Subprocess.check_call(%w{./bin/dot-git pull}, :cwd => dot_stripe, :env => useful_env)
          end
        end

        step 'gpg-sign their key' do
          complete? do
            mgr.gpg_key ||
              Subprocess.call(%W{./gnupg/is_key_signed.sh #{fingerprint}}, :cwd => dot_stripe, :env => useful_env).success?
          end

          run do
            raise "~/.stripe has uncommitted stuff in it! Clean it up, please!" unless dot_stripe_clean?
            Bundler.with_clean_env do
              Subprocess.check_call(%W{bash ./gnupg/sign_gpg_key_with_ca.sh #{fingerprint}},
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

              if output.scan(/^:pubkey enc packet: .* keyid (.+)$/).flatten.find { |keyid| fingerprint_equivalent_to_key?(keyid) }
                if mgr.gpg_key
                  log.info "Should I re-generate certs for #{stripe_email.local}? [Y/n]"
                  case $stdin.readline.chomp.downcase
                  when 'yes', 'y', ''
                    next false
                  end
                end
                true
              end
            end
          end

          run do
            if mgr.gpg_key
              # We haven't checked whether there is any uncommitted
              # stuff in ~/.stripe yet, so do it again.
              raise "~/.stripe has uncommitted stuff in it! Clean it up, please!" unless dot_stripe_clean?
            end

            Bundler.with_clean_env do
              cmdline = %w{./stripe.vpn/add_certs.sh}
              cmdline += %W{-k #{fingerprint}}
              cmdline += [stripe_email.local, stripe_email.name]
              Subprocess.check_call(cmdline, :cwd => dot_stripe, :env => useful_env)
            end
          end
        end

        commit_and_push_dot_stripe_steps { "Credential #{stripe_email.to_s} with GPG fingerprint #{fingerprint}" }

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
            hp_conn = SpaceCommander::SSH::Connection.new(user, 'hackpad2.northwest.stripe.io')
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
