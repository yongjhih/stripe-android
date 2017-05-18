# rubocop:disable PrisonGuard/NoRequireSideEffects
require "bundler/gem_tasks"
require 'rake/testtask'

Rake::TestTask.new(:test_all) do |t|
  t.pattern = "test/**/*.rb"
  t.libs = []
  # A lot of Gems that we use emit a ton of warnings, so just disable warnings
  # when running tests.
  t.warning = false
end

task :test do
  puts "Running tests..."
  Rake::Task[:test_all].invoke
end
