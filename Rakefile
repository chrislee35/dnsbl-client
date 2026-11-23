# frozen_string_literal: true

require 'bundler/gem_tasks'

require 'rake/testtask'
require 'rdoc/task'

Rake::TestTask.new do |t|
  t.libs << 'lib'
  t.test_files = FileList['test/test_*.rb']
  t.verbose = true
end

RDoc::Task.new do |rd|
  rd.main = 'README.md'
  rd.rdoc_files.include 'README.md', 'lib/**/*.rb'
  rd.options << '--all'
  rd.options << '--verbose'
end

desc 'Regenerate data/two-level-tlds and data/three-level-tlds from the Public Suffix List (optionally from a local copy of the list)'
task :update_tlds, [:source] do |_t, args|
  require 'open-uri'
  require_relative 'tasks/public_suffix_lists'

  source = args[:source]
  text = source ? File.read(source) : URI.parse(PublicSuffixLists::URL).read
  result = PublicSuffixLists.parse text
  PublicSuffixLists.write result, File.expand_path('data', __dir__)

  puts "Public Suffix List #{result.version} (commit #{result.commit})"
  PublicSuffixLists::LENGTHS.each { |length, name| puts "data/#{name}: #{result.lists[length].length} rules" }
  puts "left out (label count => rules): #{result.skipped.sort.to_h}"
end

task default: :test
