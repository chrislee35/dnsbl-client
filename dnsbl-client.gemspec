# frozen_string_literal: true

lib = File.expand_path 'lib', __dir__
$LOAD_PATH.unshift lib unless $LOAD_PATH.include? lib
require 'dnsbl/client/version'

Gem::Specification.new do |spec|
  spec.name          = 'dnsbl-client'
  spec.version       = DNSBL::Client::VERSION
  spec.authors       = ['chrislee35']
  spec.email         = ['rubygems@chrislee.dhs.org']
  spec.description   = 'simple interface to lookup blacklists results'
  spec.summary       = 'queries various DNS Blacklists'
  spec.homepage      = 'http://github.com/chrislee35/dnsbl-client'
  spec.license       = 'MIT'

  spec.files         = Dir['lib/*.rb'] + Dir['lib/**/*.rb'] + Dir['bin/*']
  spec.files        += Dir['data/*'] + Dir['test/*']
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep %r{^(test|spec|features)/}
  spec.require_paths = ['lib']
  spec.required_ruby_version = '>= 2.7'

  spec.add_development_dependency 'bundler', '~> 2.3'
  spec.add_development_dependency 'rake', '~> 13'
end
