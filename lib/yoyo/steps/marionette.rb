module Yoyo; module Steps
  class Marionette < Yoyo::StepList
    def marionette_dns; mgr.puppet_endpoint; end
    def marionette_ssh; mgr.puppet_server; end

    def init_steps
      step 'set up facts' do
        idempotent

        run do
          mgr.ssh_root.check_call! %w{mkdir -p /etc/stripe/facts}
          mgr.ssh_root.file_write('/etc/stripe/facts/user.txt',
                                  mgr.username + "\n")
          if mgr.stripe_username
            mgr.ssh_root.file_write('/etc/stripe/facts/username.txt',
                                    mgr.stripe_username + "\n")
          end
          mgr.ssh_root.file_write('/etc/stripe/facts/certname.txt',
                                  mgr.target_certname + "\n")
          if mgr.gpg_key
            mgr.ssh_root.file_write('/etc/stripe/facts/no_gpg.txt',
                                    mgr.gpg_key + "\n")
          end
          mgr.ssh_root.check_call! %w{mkdir -p /etc/stripe/yoyo}

          if mgr.machine_number
            mgr.ssh_root.file_write('/etc/stripe/facts/machinenumber.txt',
                                    mgr.machine_number + "\n")
          end

          if mgr.puppet_endpoint
            mgr.ssh_root.file_write('/etc/stripe/facts/puppetserver.txt',
                                    marionette_dns + "\n")
          end
        end
      end

      step 'install puppet' do
        complete? do
          mgr.ssh_root.if_call! %w{which puppet}, :quiet => true
        end

        run do
          mgr.ssh_root.check_call! %w{gem update --system}
          mgr.ssh_root.check_call! %w{gem install --no-ri --no-rdoc --bindir=/usr/local/bin puppet -v ~>3.8.0}
        end
      end

      step 'authorize to marionette' do
        complete? do
          mgr.ssh_root.if_call! %w{test -e /etc/stripe/yoyo/marionette-auth}
        end

        run do
          marionette_server = SpaceCommander::Server.new(step_list.marionette_ssh)

          log.info("Cleaning up any residual puppet state...")
          mgr.ssh_root.call! %w{rm -rf /etc/puppet/ssl}
          begin
						marionette_server.ssh_cmd_check_call %W{sudo marionette-cert clean #{mgr.target_certname}}
          rescue Subprocess::NonZeroExit
            # It's fine for the cleanup to fail if no cert exists under that name.
          end

          log.info("Generating a new puppet cert on the target.")
          mgr.ssh_root.call! %W{
            /usr/local/bin/puppet agent --mkusers --test --server #{step_list.marionette_dns}
            --certname #{mgr.target_certname}}

          agent_cert = mgr.ssh_root.check_output!(
            %W{/usr/local/bin/puppet agent --test --fingerprint --digest sha256
               --certname #{mgr.target_certname}}).split.last
          server_cert = marionette_server.ssh_cmd_check_output(%W{
            sudo marionette-cert list --digest sha256 #{mgr.target_certname}})
            .split.last.delete('()')

          if agent_cert != server_cert
            log.error("PUPPET CERT FINGERPRINT MISMATCH")
            log.error("agent:  #{agent_cert}")
            log.error("server: #{server_cert}")
            raise Error.new("Puppet cert fingerprint does not match")
          end

          log.info("Puppet cert #{agent_cert} matches")

          marionette_server.ssh_cmd_check_call(%W{sudo marionette-cert sign #{mgr.target_certname}})

          mgr.ssh_root.check_call! %w{touch /etc/stripe/yoyo/marionette-auth}
        end
      end

      step 'run marionette' do
        complete? do
          mgr.ssh_root.if_call! %w{test -e /etc/stripe/yoyo/puppet.initialized}
        end

        run do
          out, err, status = mgr.ssh_root.exec!("cd /;" +
            " unset TMPDIR;" +
            " /usr/local/bin/puppet agent --test --server '#{step_list.marionette_dns}'" +
            " --certname '#{mgr.target_certname}'")

          if status == 0 || status == 2
            log.info "Puppet run succeeded"
          else
            log.error "Puppet exited with status #{status}"
            raise Error.new("Marionette puppet run failed")
          end

          unless mgr.ssh_root.if_call! %w{test
              -e /etc/stripe/yoyo/puppet.initialized}
            log.error("Something went wrong. Expected sentinel file to exist!")
            raise Error.new("not found: /etc/stripe/yoyo/puppet.initialized")
          end
        end
      end
    end
  end
end; end
