require 'sixword'
require 'space-commander'

module Yoyo
  class Manager
    attr_reader :ip_address, :username, :stripe_username, :puppet_groups, :gpg_key

    def initialize(ip_address, username, options={})
      @ip_address = ip_address
      @username = username
      @stripe_username = options[:stripe_user]
      @skip_certs = true if options[:no_certs]
      @gpg_key = options[:gpg_key]
      @puppet_groups = options[:groups]

      log.info("Preparing to spin up #{username}@#{ip_address}")
    end

    def log
      @log ||= SpaceCommander::StripeLogger.new('yoyo')
    end

    def spin_up!
      log.info("Starting spin_up!")

      step_classes = [
        Yoyo::Steps::Marionette,
      ]
      step_classes << Yoyo::Steps::GenerateCredentials unless @skip_certs


      step_classes.each do |klass|
        log.info('Beginning step list: ' + klass.name)
        steplist = klass.new(self)
        steplist.run!
      end

      log.info("Finished spin_up!")
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
      @ssh_root ||= ssh!('root', :keys_only => true, :auth_methods => %w{publickey})
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
    rescue Net::SSH::AuthenticationFailed
      false
    end

    def deploy_authorized_keys!
      log.info("Deploying #{local_ssh_pubkey} to target authorized_keys")
      pubkey = File.read(local_ssh_pubkey)

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

    def local_ssh_pubkey
      File.expand_path('~/.ssh/id_rsa.pub')
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
