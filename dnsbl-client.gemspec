# frozen_string_literal: true

require_relative 'lib/dnsbl/client/version'

Gem::Specification.new do |spec|
  spec.name          = 'dnsbl-client'
  spec.version       = DNSBL::Client::VERSION
  spec.authors       = ['chrislee35']
  spec.email         = ['rubygems@chrislee.dhs.org']
  spec.description   = 'simple interface to lookup blacklists results'
  spec.summary       = 'queries various DNS Blacklists'
  spec.homepage      = 'https://github.com/chrislee35/dnsbl-client'
  spec.license       = 'MIT'

  spec.metadata = {
    'source_code_uri' => spec.homepage,
    'bug_tracker_uri' => "#{spec.homepage}/issues",
    'changelog_uri' => "#{spec.homepage}/blob/master/CHANGELOG.md",
    'documentation_uri' => 'https://chrislee35.github.io/dnsbl-client/',
    'rubygems_mfa_required' => 'true'
  }

  spec.files         = Dir['lib/**/*.rb', 'bin/*', 'data/*', 'LICENSE.txt', 'README.md', 'CHANGELOG.md']
  spec.bindir        = 'bin'
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']
  spec.required_ruby_version = '>= 3.2'

  spec.add_development_dependency 'minitest', '~> 6.0'
  spec.add_development_dependency 'rake', '~> 13.0'
  spec.add_development_dependency 'rubocop', '~> 1.0'
  spec.add_development_dependency 'rubocop-performance', '~> 1.0'
end
