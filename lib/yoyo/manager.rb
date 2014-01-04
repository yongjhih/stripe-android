require 'sixword'
require 'space-commander'

module Yoyo
  class Manager
    attr_reader :ip_address, :username

    def initialize(ip_address, username, full_name=nil)
      @ip_address = ip_address
      @username = username
      @full_name = full_name

      if full_name
        log.info("Preparing to spin up #{ip_address} for #{user_full_email}")
      else
        log.info("Preparing to spin up #{ip_address}")
      end
    end

    def full_name
      @full_name or raise ArgumentError.new(
        "full_name was not provided when this Manager was initialized")
    end

    def user_full_email
      "#{full_name} <#{username}@stripe.com>"
    end

    def log
      @log ||= SpaceCommander::StripeLogger.new('yoyo')
    end

    def spin_up!
      log.info("Starting spin_up!")

      step_classes = [
        Yoyo::Steps::Marionette,
      ]

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
      @ssh_root ||= ssh!('root')
    end

    def ssh!(user)
      log.debug "Starting SSH connection for #{user}"
      ssh_known_hosts_file = File.expand_path('~/.ssh/known_hosts-yoyo')
      begin
        SpaceCommander::SSH::Connection.new(user, ip_address,
          :user_known_hosts_file => ssh_known_hosts_file)
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

    def deploy_authorized_keys!
      log.info("Deploying #{local_ssh_pubkey} to target authorized_keys")
      pubkey = File.read(local_ssh_pubkey)

      dir = File.join(target_home, '.ssh')
      ssh.check_call! %W{mkdir -vp #{dir}}
      ssh.file_write(File.join(dir, 'authorized_keys'), pubkey)
    end

    def disable_ssh!
      log.warn("Removing remote authorized_keys and disabling ssh")
      ssh_root.check_call_shell! 'rm ~/.ssh/authorized_keys'
      ssh.check_call_shell! 'rm ~/.ssh/authorized_keys'
      ssh_root.check_call!(%w{systemsetup -setremotelogin off},
                           :input => "yes\n")
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
