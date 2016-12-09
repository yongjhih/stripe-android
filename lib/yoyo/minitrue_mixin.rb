module Yoyo
  # Mixin module containing helper functions for GPG smartcard / minitrue usage
  module MinitrueMixin
    MINITRUE_REGIONS = %w{iad sfo pdx}

    def gpg_smartcard_ready?
      Subprocess.check_call(%w{gpg --no-tty --card-status}, cwd: '/', stdout: nil, stderr: nil)
    rescue Subprocess::NonZeroExit
      false
    end

    def minitrue_admin_cert
      File.expand_path('~/.stripe-ca/admin.crt')
    end
  end
end
