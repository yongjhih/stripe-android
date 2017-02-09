require 'sixword'
require 'space-commander'

module Yoyo
  class Manager
    attr_reader :ip_address, :username, :stripe_username, :puppet_groups, :machine_number
    attr_reader :gpg_signing_identities
    attr_reader :puppet_server, :puppet_endpoint
    attr_accessor :gpg_key

    def initialize(ip_address, username, options={})
      @ip_address = ip_address
      @username = username
      @stripe_username = options[:stripe_user]
      @skip_certs = true if options[:no_certs]
      @gpg_key = options[:gpg_key]
      @puppet_groups = options[:groups]
      @machine_number = options[:machine_number]
      @gpg_signing_identities = options.fetch(:gpg_signing_identities, ['ca'])
      @puppet_server = options[:puppet_server]
      @puppet_endpoint = options[:puppet_endpoint]

      log.info("Preparing to spin up #{username}@#{ip_address}")
    end

    def log
      @log ||= SpaceCommander::StripeLogger.new('yoyo')
    end

    def run_steps(step_classes)
      step_classes.each do |klass|
        next if klass.nil?

        log.info('Beginning step list: ' + klass.name)
        steplist = klass.new(self)
        steplist.run!
      end
    end

    def spin_up!
      log.info("Starting spin_up!")

      run_steps([
                  Yoyo::Steps::Marionette,
                  (@skip_certs ? nil : Yoyo::Steps::GenerateCredentials),
                  ((@skip_certs || @gpg_key) ? nil : Yoyo::Steps::GPGSign)
                ])
      log.info("Finished spin_up!")
    end

    def decredential_user!
      log.info("Starting decredential_user!")
      run_steps([
                  Yoyo::Steps::DecredentialUser,
                  Yoyo::Steps::GPGRevokeAll
                ])
    end

    def sign_gpg_key!
      log.info("Starting GPG signing process")
      run_steps([
                  Yoyo::Steps::GPGSign
                ])
    end

    def revoke_gpg_key!
      log.info("Starting GPG revocation process")
      run_steps([
                  Yoyo::Steps::GPGRevoke
                ])
    end

    def target_serial
      @target_serial ||= get_target_serial
    end

    def target_certname
      "#{target_serial.downcase}.serial.local"
    end

    def target_home
      @target_home ||= ssh.check_call_shell!(
        'echo "$HOME"', :quiet => true).first.chomp
    end

    def ssh
      @ssh ||= ssh!(username)
    end

    def ssh_root
      @ssh_root ||= ssh!('root', :keys_only => true, :auth_methods => %w{publickey},
        # :verbose => Logger::DEBUG,  # Useful when debugging (:
        :keys => [first_local_privkey],
        )
    end

    def ssh_known_hosts_file
      File.expand_path('~/.ssh/known_hosts-yoyo')
    end

    def ssh!(user, opts={})
      log.debug "Starting SSH connection for #{user}"
      begin
        SpaceCommander::SSH::Connection.new(user, ip_address,
                                            opts.merge(:user_known_hosts_file => ssh_known_hosts_file))
      rescue Net::SSH::HostKeyUnknown => err
        fingerprint = ssh_prompt_for_fingerprint
        if fingerprint == err.fingerprint
          log.info "Fingerprint matches, retrying connection"
          err.remember_host!
          retry
        else
          log.error "Fingerprint does not match"
          raise
        end
      end
    end

    def ssh_prompt_for_fingerprint
      puts "Please enter the encoded SSH fingerprint."
      puts "This will be two lines of six words each. End with a blank line."

      input = ''
      while true
        line = STDIN.readline
        input << line
        break if line.chomp.empty?
      end

      data = Sixword.decode(input)
      colons = Sixword::Hex.encode_colons(data)

      log.debug("Decoded fingerprint to: #{colons}")

      colons
    end

    def keys_deployed?
      ssh_root.check_call!(%w{true})
      true
    rescue Net::SSH::AuthenticationFailed => e
      log.debug("Couldn't authenticate: " + e.to_s)
      false
    end

    def deploy_authorized_keys!
      log.info("Deploying local SSH pubkey to target authorized_keys")
      pubkey = first_local_pubkey

      dir = File.join(target_home, '.ssh')
      ssh.check_call! %W{mkdir -vp #{dir}}
      ssh.file_write(File.join(dir, 'authorized_keys'), pubkey)
      until keys_deployed?
        log.debug("Root is not yet authorized. Waiting...")
        sleep 1
      end
    end

    def disable_ssh!
      log.warn("Removing remote authorized_keys and disabling ssh")
      ssh_root.check_call_shell! 'rm ~/.ssh/authorized_keys'
      ssh.check_call_shell! 'rm ~/.ssh/authorized_keys'
      ssh_root.check_call!(%w{systemsetup -setremotelogin off},
                           :input => "yes\n")
      log.info("\n\nDisabled SSH access on the remote machine - deleting the local known_hosts entry...")
      entries = File.readlines(ssh_known_hosts_file)
      entries.reject! { |entry| entry =~ /^#{ip_address} / }
      File.write(ssh_known_hosts_file, entries.join("\n"))
      log.info("Done!")
    end

    def first_local_pubkey
      Subprocess.check_output(%w{ssh-add -L}).split("\n").first
    end

    def first_local_privkey
      first_local_pubkey.split(/\s/, 3)[2]
    end

    def utility_binary(name)
      File.expand_path(File.join('..', '..', 'bin', name), File.dirname(__FILE__))
    end

    def gpg_ramdisk_name
      "stripe_gpg_#{gpg_key}"
    end

    def update_gpg_key(key)
      @gpg_key = key
    end

    private

    def get_target_serial
      cmd = %w{system_profiler SPHardwareDataType}
      out, _, _ = ssh.check_call!(cmd, :quiet => true)
      line = out.split("\n").grep(/\A\s*Serial Number \(system\):/).first
      unless line
        raise Error.new("No serial number in output: " + out.inspect)
      end

      return line.split(" ").last
    end
  end
end
