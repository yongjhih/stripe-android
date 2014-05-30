require 'mail'

module Yoyo
  # Verify an ascii-armored OpenPGP block.
  class GPGVerifier
    module Error
      class NotValidated < StandardError ; end
      class GPGOutputBroken < NotValidated; end
      class UnexpectedResult < NotValidated; end
    end

    # The data, as verified (or not) by gpg
    attr_reader :data

    # The address of the key that made a valid signature
    attr_reader :signature_address

    # The full fingerprint of the key that made a valid signature
    attr_reader :signature_fpr

    GPG_PREFIX="[GNUPG:] "
    GPG_MUST_HAVE_KEYWORDS = Set.new(%w{GOODSIG VALIDSIG TRUST_FULLY})
    GPG_MUST_NOT_HAVE_KEYWORDS = Set.new(%w{EXPKEYSIG TRUST_UNDEFINED REVKEYSIG KEYREVOKED TRUST_NEVER})

    def initialize
      @data = ""
    end

    # Launch GPG, have it read and verify ascii-armored data from stdin
    # @raise [Error::NotValidated] (or a subclass) if the verification process fails
    # @return [String] the validated result
    def read_ascii_armor_data
      log.info "Please paste the OpenPGP block from the email you just got:"
      read, write = IO.pipe
      log.debug("Write FD number is #{write.to_i}")
      gpg_command = %W{gpg --no-verbose --quiet --no-tty --status-fd #{write.to_i}}
      log.debug("Running #{gpg_command}")
      verify_result = ""
      data = ""
      process = Subprocess.check_call(gpg_command,
                            :stdout => Subprocess::PIPE,
                            :stderr => nil,
                            :retain_fds => [write.to_i]) do |process|
        write.close
        verify_done = false
        key_done = false

        until verify_done && key_done
          verify_done ||= process.drain_fd(read, verify_result)
          key_done ||= process.drain_fd(process.stdout, data)
        end
        process.wait

        log.debug("Verify_done=#{verify_done.inspect} key_done=#{key_done.inspect}, #{process.inspect}")
        log.debug("Got verify result:\n#{verify_result}")
        log.debug("Got key:\n#{@data}")
      end
      @data = data
      verify_signature(verify_result)
    end

    private

    def verify_signature(gpg_status)
      lines = gpg_status.split("\n").map do |line|
        if line.start_with?(GPG_PREFIX)
          line[(GPG_PREFIX.length)..-1]
        else
          raise Error::GPGOutputBroken.new("Encountered line #{line.inspect} - can't deal.")
        end
      end

      status = {}
      lines.each do |line|
        keyword, args = line.split(' ', 2)
        status[keyword] = args
      end

      has_keywords = status.keys
      unless (missing_keywords = GPG_MUST_HAVE_KEYWORDS - has_keywords).empty?
        raise Error::UnexpectedResult.new("Was expecting verification keywords #{GPG_MUST_HAVE_KEYWORDS}, got #{has_keywords}; missing #{missing_keywords.to_a}")
      end

      unless (had_keywords = GPG_MUST_NOT_HAVE_KEYWORDS.intersection(has_keywords)).empty?
        raise Error::UnexpectedResult.new("Was not expecting verification keywords #{had_keywords.to_a} in #{has_keywords}")
      end

      # Now, extract the interesting pieces of data.
      # First, the Stripe # user name and full name:
      keyid, name = status['GOODSIG'].split(' ', 2)
      log.debug("Got signature by key #{keyid}, handle #{name}")
      @signature_address = Mail::Address.new(name)

      # Now, the key's fingerprint:
      @signature_fpr, _ = status['VALIDSIG'].split(' ', 2)

      true
    end

    def log
      @log ||= SpaceCommander::StripeLogger.new('yoyo')
    end
  end
end
