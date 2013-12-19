require 'docile'

module Yoyo
  class StepList
    @abstract = true

    def self.abstract?
      !!@abstract
    end

    attr_reader :steps, :mgr

    def initialize(manager)
      if self.class.abstract?
        raise ArgumentError.new("This is an abstract step list")
      end

      init_steps

      @mgr = manager
    end

    def init_steps
      raise NotImplementedError.new("must override init_steps")
    end

    def log
      @log ||= SC::StripeLogger.new(self.class.name.split('::').last)
    end

    def run!
      log.info("Beginning run! of step list")
      steps.each do |step|
        step.run_as_needed!
      end
    end

    private

    # hack so Steps can access the StepList object
    def step_list
      self
    end

    def step(name, &blk)
      raise ArgumentError.new("block is required") unless blk

      step = Docile.dsl_eval(Yoyo::Step::Builder.new, &blk).build(name)

      @steps ||= []
      @steps << step
    end
  end
end
