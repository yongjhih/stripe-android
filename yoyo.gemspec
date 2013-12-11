# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'yoyo/version'

Gem::Specification.new do |spec|
  spec.name          = "yoyo"
  spec.version       = Yoyo::VERSION
  spec.authors       = ["Andy Brody"]
  spec.email         = ["andy@stripe.com"]
  spec.summary       = 'Spin up new machines for use'
  spec.description   = <<-EOM
    Yoyo automates several pieces of the spin-up and credentialing process.
  EOM
  spec.homepage      = "https://github.com/stripe-internal/yoyo.git"
  spec.license       = "Proprietary"

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.3"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "pry"

  spec.add_dependency 'sixword'
  spec.add_dependency 'subprocess'
  spec.add_dependency 'space-commander'
  spec.add_dependency 'highline'
end
