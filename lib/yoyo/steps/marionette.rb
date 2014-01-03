module Yoyo; module Steps
  class Marionette < Yoyo::StepList
    def init_steps
      step 'set up facts' do
        idempotent
        run do
          mgr.ssh_root.check_call! %w{mkdir -p /etc/stripe/facts}
          mgr.ssh_root.file_write('/etc/stripe/facts/user.txt',
                                  mgr.username + "\n")
          mgr.ssh_root.file_write('/etc/stripe/facts/certname.txt',
                                  mgr.target_certname + "\n")
        end
      end

      step 'install puppet' do
        complete? do
          mgr.ssh_root.if_call! %w{which puppet}, :quiet => true
        end
        run do
          mgr.ssh_root.check_call! %w{gem update --system}
          mgr.ssh_root.check_call! %w{gem install --no-ri --no-rdoc puppet}
        end
      end

      step 'authorize to marionette' do
        complete? do
          mgr.ssh_root.if_call! %w{test -e /etc/stripe/yoyo/marionette-auth}
        end
        run do
          marionette_dns = 'marionette.stripe.com'
          marionette_ssh = 'marionette1.stripe.io'
          certname = mgr.target_certname

          mgr.ssh_root.call! %W{
            puppet agent --mkusers --test --server #{marionette_dns}
            --certname #{certname}}

          agent_cert = mgr.ssh_root.check_output!(
            %W{puppet agent --test --fingerprint --digest sha256
               --certname #{certname}}).split.last
          server_cert = Subprocess.check_output(%W{
            ssh #{marionette_ssh} marionette-cert list --digest sha256
                #{certname}}).split.last.delete('()')

          if agent_cert != server_cert
            log.error("PUPPET CERT FINGERPRINT MISMATCH")
            log.error("agent:  #{agent_cert}")
            log.error("server: #{server_cert}")
            raise Error.new("Puppet cert fingerprint does not match")
          end

          log.info("Puppet cert #{agent_cert} matches")

          Subprocess.check_output(%W{
            ssh #{marionette_ssh} marionette-cert sign #{mgr.target_certname}})

          mgr.ssh_root.check_call_shell!('mkdir -p /etc/stripe/yoyo;
            touch /etc/stripe/yoyo/marionette-auth')
        end
      end
    end
  end
end; end
