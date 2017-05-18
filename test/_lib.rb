require 'minitest/autorun'
require 'minitest/spec'
require 'mocha/setup'

require_relative '../lib/yoyo'

module Critic
  class Test < ::MiniTest::Spec
    def before_setup
      # Stub all Excon operations by default.
      Excon.defaults[:mock] = true
    end

    def after_teardown
      # Remove all excon stubs
      Excon.stubs.clear
    end

    def setup
      # Put any stubs here that you want to apply globally
    end
  end
end
