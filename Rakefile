require 'rubygems'
require 'bundler'
begin
	Bundler.setup(:default, :development)
rescue Bundler::BundlerError => e
	$stderr.puts e.message
	$stderr.puts "Run `bundle install` to install missing gems"
	exit e.status_code
end
require 'rake'

require 'jeweler'
Jeweler::Tasks.new do |gem|
	# gem is a Gem::Specification... see http://docs.rubygems.org/read/chapter/20 for more options
	gem.name = "dnsbl-client"
	gem.homepage = "http://github.com/chrislee35/dnsbl-client"
	gem.license = "MIT"
	gem.summary = %Q{queries various DNS Blacklists}
	gem.description = %Q{simple interface to lookup blacklists results}
	gem.email = "rubygems@chrislee.dhs.org"
	gem.authors = ["Chris Lee"]
	gem.signing_key = "#{File.dirname(__FILE__)}/../gem-private_key.pem"
	gem.cert_chain  = ["#{File.dirname(__FILE__)}/../gem-public_cert.pem"]
	gem.files = FileList["{bin,lib}/**/*"].to_a
	gem.executables = ["dnsbl-client"]
end
Jeweler::RubygemsDotOrgTasks.new

require 'rake/testtask'
Rake::TestTask.new(:test) do |test|
	test.libs << 'lib' << 'test'
	test.pattern = 'test/**/test_*.rb'
	test.verbose = true
end

require 'rcov/rcovtask'
Rcov::RcovTask.new do |test|
	test.libs << 'test'
	test.pattern = 'test/**/test_*.rb'
	test.verbose = true
end

task :default => :test

require 'rake/rdoctask'
Rake::RDocTask.new do |rdoc|
	version = File.exist?('VERSION') ? File.read('VERSION') : ""

	rdoc.rdoc_dir = 'rdoc'
	rdoc.title = "dnsbl-client #{version}"
	rdoc.rdoc_files.include('README*')
	rdoc.rdoc_files.include('lib/**/*.rb')
end
