module Yoyo
  class Step
    attr_reader :name

    def initialize(name, run_block, complete_block, idempotent)
      raise ArgumentError.new("Must provide run block") unless run_block

      if complete_block && idempotent
        raise ArgumentError.new(
          "Idempotent step should not have complete? block")
      end

      @name = name
      @run_block = run_block
      @complete_block = complete_block
      @idempotent = idempotent
    end

    def log
      @log ||= SpaceCommander::StripeLogger.new("Step(#{@name})")
    end

    def idempotent?
      !!@idempotent
    end

    def complete?
      @complete_block.call
    end

    def run!
      log.info('running...')
      @run_block.call
      log.info('finished run')
    end

    def run_as_needed!
      if !idempotent? && complete?
        log.info('already complete')
        return
      end
      run!
    end

    class Builder
      # what even is a builder pattern??
      def build(name)
        Yoyo::Step.new(name, @run_block, @complete_block, @idempotent)
      end

      def run(&blk)
        raise ArgumentError.new("must provide block") unless blk
        @run_block = blk
        self
      end

      def complete?(&blk)
        raise ArgumentError.new("must provide block") unless blk
        @complete_block = blk
        self
      end

      def idempotent
        @idempotent = true
        self
      end
    end
  end
end
