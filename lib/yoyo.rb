require 'subprocess'
require 'bundler/setup'

require_relative 'yoyo/version'

module Yoyo
end

require_relative 'yoyo/errors'

#require_relative 'yoyo/bootstrap-step'
#require_relative 'yoyo/steps'
require_relative 'yoyo/manager'
