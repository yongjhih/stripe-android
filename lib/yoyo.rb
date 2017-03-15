require 'bundler/setup'

require 'subprocess'
require_relative 'yoyo/version'

module Yoyo
end

require_relative 'yoyo/cli'
require_relative 'yoyo/errors'

require_relative 'yoyo/ssh'

require_relative 'yoyo/dot_stripe_mixin'
require_relative 'yoyo/ldapmanager_mixin'
require_relative 'yoyo/minitrue_mixin'
require_relative 'yoyo/github_enterprise_client'

require_relative 'yoyo/step'
require_relative 'yoyo/step-list'
require_relative 'yoyo/manager'
require_relative 'yoyo/steps'

require_relative 'yoyo/gpg_verifier'
