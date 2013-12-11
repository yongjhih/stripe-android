require 'sixword'
require 'space-commander'

module Yoyo
  class Manager
    attr_reader :ip_address, :username, :full_name

    def initialize(ip_address, username, full_name)
      @ip_address = ip_address
      @username = username
      @full_name = full_name

      log.info("Preparing to spin up #{ip_address} for #{user_full_email}")
    end

    def user_full_email
      "#{full_name} <#{username}@stripe.com>"
    end

    def log
      @log ||= SpaceCommander::StripeLogger.new('yoyo')
    end

    def run!
    end

    def ssh
      return @ssh if @ssh
      ssh!
    end

    def ssh!
      log.debug "Starting SSH connection"
      ssh_known_hosts_file = File.expand_path('~/.ssh/known_hosts-yoyo')
      begin
        @ssh = SpaceCommander::SSH::Connection.new(ip_address, username,
          :user_known_hosts_file => ssh_known_hosts_file)
      rescue Net::SSH::HostKeyUnknown => err
        fingerprint = ssh_prompt_for_fingerprint
        if fingerprint == err.fingerprint
          log.info "Fingerprint matches, retrying connection"
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
  end
end
