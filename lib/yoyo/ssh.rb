require 'net/ssh'
require 'net/ssh/gateway'
require 'net/sftp'

module Yoyo
  module SSH
    class CommandError < RuntimeError
      attr_reader :reason, :code
      def initialize(reason, code=nil)
        @reason = reason
        @code = code
        super code ? "#{reason} #{code}" : reason.to_s
      end
    end

    unless defined?(Net::SSH::HostKeyUnknown)
      version = Net::SSH::Version::CURRENT.to_s
      warn("WARNING: loaded Net::SSH #{version} without host key patch")
      warn('WARNING: Yoyo::SSH::Conection will probably fail')
    end

    class Connection
      attr_reader :log, :conn, :sudo, :spec, :gateway

      def initialize(user, host, opts={})
        @user = user
        @host = host
        @opts = opts.clone
        # Net::SSH has stupid verification defaults
        @opts[:paranoid] ||= :secure

        # Send keepalives, so that a lost l2 connection doesn't make
        # connections appear hung:
        unless @opts.has_key?(:keepalive)
          @opts[:keepalive] = true
          @opts[:keepalive_interval] = 15
        end

        @spec = "#{user}@#{host}"
        @spec << ":#{@opts[:port]}" if @opts[:port]

        @log = SpaceCommander::StripeLogger.new("ssh")

        reconnect!
      end

      def close
        if @conn.closed?
          @log.debug("Connection already closed")
        else
          @conn.close
          @log.debug("Connection closed")
        end

        if @gateway
          @gateway.shutdown!
          @log.debug("Gateway shut down")
        end
      end

      def inspect
        s = "#<SSH::Connection @spec=#{@spec.inspect}"
        s << " @gw_spec=#{@gw_spec.inspect}" if @gw_spec
        s << " @sudo=#{@sudo.inspect}>"
      end

      def sudo=(val)
        @sudo = val
        if val
          @log.debug('Commands sent to call! will be run with sudo')
        else
          @log.debug('Commands sent to call! will NOT be run with sudo')
        end
      end

      # Escape a string so it is treated by the shell as a single word.
      def self.escape_shell_arg(arg)
        # Replace all ' with '\'' and surround with '
        "'" + arg.gsub("'") {"'\\''"} + "'"
      end

      # Escape an array so each element is treated as a single word.
      def self.escape_shell_cmd(cmd)
        unless cmd.respond_to? :join
          raise ArgumentError.new('cmd should be an Array or similar')
        end

        cmd.map {|x| self.escape_shell_arg(x)}.join(' ')
      end

      # Run an array of arguments on the remote host.
      #
      # The array elements will be escaped so they are passed safely to the
      # shell without being interpreted specially. All characters except NUL
      # are safe.
      #
      # If @sudo is true, commands will be prefixed with 'sudo'.
      #
      def call!(cmd_arr, opts={})
        opts = {quiet: false}.merge(opts)
        sudo = opts[:sudo]
        sudo = @sudo if sudo.nil?
        cmd_arr = ['sudo'] + cmd_arr if sudo
        cmd = self.class.escape_shell_cmd(cmd_arr)
        exec!(cmd, opts)
      end

      # Run an array of arguments on the remote host, and raise an exception on
      # nonzero exit status.
      #
      # The array elements will be escaped so they are passed safely to the
      # shell without being interpreted specially. All characters except NUL
      # are safe.
      #
      # If @sudo is true, commands will be prefixed with 'sudo'.
      #
      def check_call!(cmd_arr, opts={})
        opts = {quiet: false, check_status: true}.merge(opts)
        call!(cmd_arr, opts)
      end

      # Run an array of arguments on the remote host, returning output from
      # stdout, and raising an exception on nonzero exit status.
      def check_output!(cmd_arr, opts={})
        opts = {print_stdout: false, check_status: true}.merge(opts)
        out, err, status = call!(cmd_arr, opts)
        return out
      end

      # Run an array of arguments on the remote host, and return true if it
      # exits with status zero. This is a convenience method for emulating
      # the behavior of the shell 'if' command.
      def if_call!(cmd_arr, opts={})
        _, _, status = call!(cmd_arr, opts)
        return (status == 0)
      end

      # Pass line to a shell (/bin/sh) to be interpreted. This is similar to
      # exec!, but if @sudo is true, the shell will be run with sudo.
      def call_shell!(line, opts={})
        call!(['sh', '-c', line], opts)
      end

      # Pass line to a shell (/bin/sh) to be interpreted. If the shell exits
      # with nonzero status, raise an exception. This is equivalent to
      # call_shell! with :check_status => true.
      def check_call_shell!(line, opts={})
        opts = {check_status: true}.merge(opts)
        call_shell!(line, opts)
      end

      # Read specified file path from the remote server.
      def file_read(path, sudo=nil)
        sudo = @sudo if sudo.nil?

        cmd = sudo ? ['sudo'] : []
        cmd += ['cat', '--', path]

        check_call!(cmd, quiet: true)[0]
      end

      # Write specified file path on the remote server.
      def file_write(path, data, sudo=nil, append=false)
        sudo = @sudo if sudo.nil?

        cmd = sudo ? 'sudo ' : ''
        cmd << 'tee'
        cmd << ' -a' if append
        cmd << ' -- ' + self.class.escape_shell_arg(path)
        cmd << ' >/dev/null'

        exec!(cmd, check_status: true, input: data)
      end

      # Append to specified file path on the remote server.
      def file_append(path, data, sudo=nil)
        file_write(path, data, sudo, true)
      end

      def file_exists?(path)
        if_call!(['test', '-f', path])
      end

      def sftp
        # requires net-sftp
        @conn.sftp
      end

      private

      def reconnect!
        @log.info("Connecting to #{@spec}")
        host = @host
        port = @opts[:port]

        if @opts[:gateway]
          g_user, g_host, g_opts = @opts.delete(:gateway)
          @gw_spec = "#{g_user}@#{g_host}"
          @gw_spec << ":#{g_opts[:port]}" if g_opts[:port]
          @log.info("Using #{@gw_spec} as a gateway")

          g_opts = g_opts.merge(paranoid: @opts[:paranoid],
                                timeout: @opts[:timeout],
                                keepalive: @opts[:keepalive],
                                keepalive_interval: @opts[:keepalive_interval])

          @gateway = Net::SSH::Gateway.new(g_host, g_user, g_opts)
          @log.info("Connected to gateway")

          real_host = host
          host = '127.0.0.1'

          # Use a random high port for the local listener.
          # (from /proc/sys/net/ipv4/ip_local_port_range)
          high_port = 61000
          low_port = 32768

          begin
            local_port = rand(high_port - low_port) + low_port
            @gateway.open(real_host, port, local_port)
          rescue Errno::EADDRINUSE
            @log.info("EADDRINUSE -- trying another local port")
            retry
          end

          port = local_port
          @log.info("Gateway forward succeeded")
        end

        if @opts[:keys]
          # Tell net/ssh to try the keys explicitly requested first,
          # so we don't get locked out before it tries the ones likely
          # to work:
          @opts[:keys_only] = true
        end

        begin
          @conn = Net::SSH.start(host, @user, @opts.merge(port: port))
        rescue => e
          @log.warn("Connection failed: " + e.inspect)
          if @gateway
            # clean up gateway if the main connection fails
            @log.warn("Shutting down gateway")
            begin
              @gateway.shutdown!
            rescue
            end
          end
          raise
        end
        @log.debug("Connected")
      rescue Net::SSH::AuthenticationFailed
        @log.error("Authentication failed. Maybe you need to ssh-add the key?")
        raise
      end

      def reconnect_if_needed!
        # Send a keepalive ping, which should fail if the connection died in the meantime.
        begin
          @conn.send_global_request('keepalive@openssh.com')
          @conn.process(1)
        rescue Net::SSH::Disconnect
          reconnect!
        end
      end

      # Run a command string on the remote host.
      #
      # The command will be run by the login shell or potentially by a
      # ForceCommand script if specified by the server.
      #
      # @param cmd [String] the command string to runc
      # @param opts [Hash]  various options to control execution
      #
      # @option opts :quiet [Boolean] When true, disables :print_stdout and
      #   :print_stderr.
      # @option opts :print_stdout [Boolean] (true) Reprint stdout from remote.
      # @option opts :print_stderr [Boolean] (true) Reprint stderr from remote.
      # @option opts :collect_stdout [Boolean] (true) Collect stdout in a
      #   StringIO and return it when finished.
      # @option opts :collect_stderr [Boolean] (true) Collect stderr in a
      #   StringIO and return it when finished.
      # @option opts :check_status [Boolean] When true, an exception will be
      #   raised on nonzero exit.
      # @option opts :input [String] Write data to the channel's stdin.
      # @option opts :pty [Boolean] When true, request a pty for the channel.
      # @option opts :locale_env [Boolean] (true) When true, try to set locale
      #   environment variables on the remote host. This is subject to the sshd
      #   server's AcceptEnv configuration, but is probably LANG LC_*.
      # @option opts :connect_stdin [Boolean] Connect the local standard input
      #   to the remote process's standard input. WARNING: This is experimental
      #   and may do horrible things like segfault or deadlock.
      #
      def exec!(cmd, opts={})
        reconnect_if_needed!

        opts = {print_stdout: true, print_stderr: true,
                collect_stdout: true, collect_stderr: true,
                locale_env: true}.merge(opts)
        if opts[:quiet]
          opts[:print_stdout] = false
          opts[:print_stderr] = false
        end

        if opts.fetch(:collect_stdout)
          stdout = StringIO.new
        else
          stdout = nil
        end
        if opts.fetch(:collect_stderr)
          stderr = StringIO.new
        else
          stderr = nil
        end
        status = nil

        if cmd.is_a? Array
          # Net::SSH doesn't validate its arguments. (WTF)
          # If you pass an Array it disconnects with "Packet integrity error."
          raise ArgumentError.new('cmd should be a String')
        end

        ch = @conn.open_channel do |ch|

          @log.debug('exec! ' + cmd.inspect)

          if opts.fetch(:locale_env)
            ENV.find_all do |k, v|
              k == 'LANG' || k.start_with?('LC_')
            end.each do |k, v|
              ch.env(k, v)
            end
          end

          if opts[:pty]
            ch.request_pty
          end

          ch.exec(cmd) do |ch, success|
            raise CommandError.new('Failed to invoke command') unless success

            ch.on_data do |c, data|
              $stdout.print data if opts.fetch(:print_stdout)
              stdout << data if opts.fetch(:collect_stdout)
            end

            ch.on_extended_data do |c, type, data|
              $stderr.print data if opts.fetch(:print_stderr)
              stderr << data if opts.fetch(:collect_stderr)
            end

            ch.on_request('exit-status') do |c, data|
              status = data.read_long

              if opts[:check_status] && status != 0
                if opts.fetch(:collect_stderr)
                  @log.warn('stderr: ' + stderr.string.inspect)
                end
                m = "Command exited with non-zero status"
                raise CommandError.new(m, status)
              end
            end

            ch.on_request('exit-signal') do |c, data|
              signal = data.read_string
              if opts.fetch(:collect_stderr)
                @log.warn('stderr: ' + stderr.string.inspect)
              end
              m = "Command killed by signal"
              raise CommandError.new(m, signal)
            end

            if opts[:input]
              ch.send_data opts[:input]
              ch.eof!
            else
              # TODO: do more things here
              unless opts[:pty]
                # indicate that no input is forthcoming
                ch.eof!
              end
            end
          end
        end

        if opts[:connect_stdin]
          input_stream = STDIN
          while ch.active?
            @conn.process(0.2)

            begin
              data = input_stream.read_nonblock(1024)
            rescue IO::WaitReadable
              # no data to read
            rescue EOFError
              ch.eof!
              break
            else
              ch.send_data(data)
            end
          end
        end

        ch.wait

        [stdout && stdout.string, stderr && stderr.string, status]
      end
    end
  end
end
