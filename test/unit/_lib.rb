require_relative '../_lib'

module Critic::Unit
  module Stubs
  end

  class Test < Critic::Test
    include Stubs
  end
end
