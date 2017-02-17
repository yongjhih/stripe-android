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

  spec.add_dependency 'docile', '~> 1.1'
  spec.add_dependency 'sixword', '~> 0.3'
  spec.add_dependency 'subprocess'
  spec.add_dependency 'space-commander'
  spec.add_dependency 'highline'
  spec.add_dependency 'mail'
  spec.add_dependency 'chalk-cli'
  spec.add_dependency 'octokit'
  spec.add_dependency 'excon'

  spec.add_dependency 'net-ssh', '~> 4.0.1.stripe.1'
	spec.add_dependency 'net-sftp', '~> 2.1.2'
	spec.add_dependency 'net-ssh-gateway', '~> 2.0.0'

	# TEMP -> move this to s-c
	spec.add_dependency 'u2f_client', '~> 0.1'
end
