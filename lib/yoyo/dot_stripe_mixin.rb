module Yoyo

  # Mixin module containing helper functions for interaction with dot-stripe

  module DotStripeMixin
    def dot_stripe
      File.expand_path("~/.stripe")
    end

    def git_dir_clean?(dir)
      # Any staged but uncommitted changes? Exit status 1 = yep.
      Subprocess.call(%w{git diff-index --quiet HEAD}, :cwd => dir).success? &&
        # Any unstaged changes? Exit status 1 = yep.
        Subprocess.call(%w{git diff-files --quiet}, :cwd => dir).success?
    end

    def dot_stripe_clean?
      git_dir_clean?(dot_stripe)
    end

    def useful_env
      Bundler.with_clean_env do
        env = ENV.to_hash
        path = env['PATH'].split(':').delete_if {|d| d.start_with?(File.expand_path('~/.rbenv/versions'))}.join(':')
        env['PATH'] = path
        env.delete('RBENV_VERSION')
        env
      end
    end

    def latest_cert
      all_certs = Dir.glob(File.expand_path("stripe.vpn/#{stripe_email.local}-[0-9]*.tar.gz.gpg", dot_stripe))
      all_certs.sort_by { |filename|
        File.stat(filename).mtime
      }.last
    end

    def commit_and_push_dot_stripe_steps(&commit_message_block)
      step 'commit ~/.stripe' do
        complete? do
          dot_stripe_clean?
        end

        run do
          log.debug("Adding files...")
          Subprocess.check_call(%w{git add .}, :cwd => dot_stripe)
          log.debug("committing...")
          Subprocess.check_call(%W{git commit -m #{commit_message_block.call}}, :cwd => dot_stripe)
        end
      end

      step 'push ~/.stripe' do
        idempotent

        run do
          Bundler.with_clean_env do
            Subprocess.check_call(%w{bin/dot-git push}, :cwd => dot_stripe, :env => useful_env)
          end
        end
      end
    end
  end
end
