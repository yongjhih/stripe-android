require 'chalk-cli'

class Yoyo::Command < Chalk::CLI::Command
  def invoke
    setup_sentry

    Raven.user_context(username: Etc.getpwuid(STDIN.stat.uid).name)
    Raven.tags_context(cli_arguments: arguments)
    Raven.tags_context(cli_options: options)

    begin
      do_invoke
    rescue Interrupt
      # Peaceful, just exit & don't report to sentry
      raise
    rescue Exception => e
      Raven.capture_exception(e)
    end
  end

  def do_invoke
    raise "Not implemented for #{self.class.name}!"
  end

  def setup_sentry
    Raven.configure do |config|
      config.silence_ready = true
      unless ENV.include?('SENTRY_DSN')
        # NOTE: This looks like a secret, but it really really is
        # not. Do NOT check in other secrets into this repo, please!
        config.dsn = 'https://3cd35d6f945a47ac97558d5232014ecc:90f6d09a136740e58fba90292f0d1ceb@errors.stripe.com/122'
      end
    end
  end
end
