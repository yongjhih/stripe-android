# Execute bundler hook if present
['~/.', '/etc/'].any? do |file|
 File.lstat(path = File.expand_path(file + 'bundle-gemfile-hook')) rescue next
 eval(File.read(path), binding, path); break true
end || source('https://rubygems.org/')

gem 'chalk-hostname', :git => 'git@github.com:stripe/chalk-hostname', :ref => 'c362f40046d2a1188bca11c969611a4bca1b9c37'
gem 'space-commander', :git => 'git@github.com:stripe-internal/space-commander', :ref => '5a02cf43f4751542276137ec0666af5c2578a5ab'

# Specify your gem's dependencies in yoyo.gemspec
gemspec
