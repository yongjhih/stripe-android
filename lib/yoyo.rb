require 'bundler/setup'

require 'subprocess'
require_relative 'yoyo/version'

module Yoyo
end

require_relative 'yoyo/errors'

require_relative 'yoyo/step'
require_relative 'yoyo/step-list'
require_relative 'yoyo/manager'
require_relative 'yoyo/steps'

require_relative 'yoyo/gpg_verifier'
