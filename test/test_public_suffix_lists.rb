# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require_relative '../tasks/public_suffix_lists'

class TestPublicSuffixLists < Minitest::Test
  LIST = <<~LIST
    // ===BEGIN ICANN DOMAINS===
    // VERSION: 2000-01-02_03-04-05_UTC
    // COMMIT: abc123
    com
    uk
    co.uk
    // a comment
    ck
    *.ck
    !www.ck
    *.nom.br
    ca.us
    k12.ca.us
    pvt.k12.ma.us
    bø.telemark.no
    co.uk
    食品.cn
    // ===END ICANN DOMAINS===
  LIST

  def test_punycode_matches_the_rfc_3492_and_idna_reference_values
    assert_equal 'xn--mnchen-3ya', PublicSuffixLists.to_ascii('münchen')
    assert_equal 'xn--bcher-kva', PublicSuffixLists.to_ascii('bücher')
    assert_equal 'xn--b-5ga', PublicSuffixLists.to_ascii('bø')
    assert_equal 'xn--3bst00m', PublicSuffixLists.to_ascii('集团')
    assert_equal 'example', PublicSuffixLists.to_ascii('example')
  end

  def test_parse_sorts_rules_into_lists_by_label_count
    result = PublicSuffixLists.parse LIST
    assert_equal %w[!www.ck *.ck ca.us co.uk xn--jvr189m.cn], result.lists[2]
    assert_equal %w[*.nom.br k12.ca.us xn--b-5ga.telemark.no], result.lists[3]
  end

  def test_parse_keeps_wildcards_and_exceptions_and_drops_long_rules
    result = PublicSuffixLists.parse LIST
    assert_includes result.lists[2], '*.ck'
    assert_includes result.lists[2], '!www.ck'
    refute(result.lists.values.flatten.any? { |rule| rule.include? 'pvt.k12' })
    assert_equal({ 1 => 3, 4 => 1 }, result.skipped)
  end

  def test_parse_removes_duplicates_and_reads_the_version
    result = PublicSuffixLists.parse LIST
    assert_equal 1, result.lists[2].count('co.uk')
    assert_equal '2000-01-02_03-04-05_UTC', result.version
    assert_equal 'abc123', result.commit
  end

  def test_write_creates_one_rule_per_line
    Dir.mktmpdir do |dir|
      PublicSuffixLists.write PublicSuffixLists.parse(LIST), dir
      assert_equal "*.nom.br\nk12.ca.us\nxn--b-5ga.telemark.no\n", File.read(File.join(dir, 'three-level-tlds'))
      assert_includes File.readlines(File.join(dir, 'two-level-tlds'), chomp: true), 'co.uk'
    end
  end
end
