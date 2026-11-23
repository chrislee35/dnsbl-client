# frozen_string_literal: true

unless Kernel.respond_to? :require_relative
  module Kernel
    def require_relative(path)
      require File.join(File.dirname(caller(1..1).first), path.to_str)
    end
  end
end

require_relative 'helper'
require 'tempfile'

class TestDNSBLClient < Minitest::Test
  NAME_SERVERS = [['4.2.2.2', 53]].freeze

  def test_return_no_hits_for_127_0_0_1
    c = DNSBL::Client.new
    c.nameservers = NAME_SERVERS
    # RFC 5782 says 127.0.0.1 must not be listed. Other candidates misbehave: DRONEBL answers 127.0.0.255 for 127.0.0.255,
    # and SPFBL answers 127.0.0.4 ("no mail service here") for 127.0.0.254 and 0.0.0.254.
    res = c.lookup '127.0.0.1'
    puts res if res.length.positive?
    assert_empty res
  end

  def test_return_all_lists_for_127_0_0_2
    skip 'not work anymore'

    c = DNSBL::Client.new
    c.nameservers = NAME_SERVERS
    res = c.lookup '127.0.0.2'
    c.dnsbls.each do |bls|
      assert res.detect { |ci| ci.dnsbl == bls }, "#{bls} missing"
    end
    assert res.count >= c.dnsbls.count
  end

  def test_encode_ipv6_query_as_reversed_nibbles
    c = DNSBL::Client.new
    msg = c.send :encode_query, '2607:f8b0:4004:805::2004', 'ip', 'example.dnsbl'
    question = Resolv::DNS::Message.decode(msg).question.first.first.to_s
    assert_equal '4.0.0.2.0.0.0.0.0.0.0.0.0.0.0.0.5.0.8.0.4.0.0.4.0.b.8.f.7.0.6.2.example.dnsbl', question
  end

  def test_encode_ipv4_query_as_reversed_octets
    c = DNSBL::Client.new
    msg = c.send :encode_query, '203.150.14.85', 'ip', 'example.dnsbl'
    assert_equal '85.14.150.203.example.dnsbl', Resolv::DNS::Message.decode(msg).question.first.first.to_s
  end

  def test_decode_ipv6_answer_to_compressed_address
    # the RFC 5782 IPv6 test entry; its nibbles start with four digits, which must not be mistaken for an IPv4 query
    c = DNSBL::Client.new
    c.add_dnsbl 'v6list', 'v6.example.dnsbl', 'ip', { '127.0.0.2' => 'Listed' }, ipv6: true
    c.instance_variable_set :@starttime, Time.now.to_f
    query = '2.0.0.0.0.0.f.7.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.v6.example.dnsbl'
    reply = Resolv::DNS::Message.new 1
    reply.add_answer query, 60, Resolv::DNS::Resource::IN::A.new('127.0.0.2')
    res = c.send :decode_response, reply.encode
    assert_equal 1, res.length
    assert_equal 'v6list', res[0].dnsbl
    assert_equal '::ffff:127.0.0.2', res[0].item
    assert_equal '127.0.0.2', res[0].result
    assert_equal 'Listed', res[0].meaning
  end

  def test_decode_ipv4_answer_still_reverses_octets
    c = DNSBL::Client.new
    c.add_dnsbl 'v4list', 'v4.example.dnsbl', 'ip', { '127.0.0.2' => 'Listed' }
    c.instance_variable_set :@starttime, Time.now.to_f
    reply = Resolv::DNS::Message.new 1
    reply.add_answer '85.14.150.203.v4.example.dnsbl', 60, Resolv::DNS::Resource::IN::A.new('127.0.0.2')
    res = c.send :decode_response, reply.encode
    assert_equal ['203.150.14.85'], res.map(&:item)
  end

  def test_decode_domain_answer_goes_to_the_list_whose_zone_it_belongs_to
    # dbl.example.dnsbl also ends with bl.example.dnsbl, so zones must be matched on a label boundary
    c = DNSBL::Client.new
    c.add_dnsbl 'IPLIST', 'bl.example.dnsbl', 'ip'
    c.add_dnsbl 'DOMAINLIST', 'dbl.example.dnsbl', 'domain'
    c.instance_variable_set :@starttime, Time.now.to_f
    reply = Resolv::DNS::Message.new 1
    reply.add_answer 'spammer.example.com.dbl.example.dnsbl', 60, Resolv::DNS::Resource::IN::A.new('127.0.0.2')
    res = c.send :decode_response, reply.encode
    assert_equal ['DOMAINLIST'], res.map(&:dnsbl)
    assert_equal ['spammer.example.com'], res.map(&:item)
  end

  def test_bitmask_lists_combine_the_meanings_of_every_flag_set
    c = DNSBL::Client.new
    c.add_dnsbl 'FLAGS', 'flags.example.dnsbl', 'domain',
                { '127.0.0.1' => 'Blocked', '127.0.0.4' => 'Disposable', '127.0.0.8' => 'Phishing', '127.0.0.64' => 'Abuse' },
                bitmask: true
    c.instance_variable_set :@starttime, Time.now.to_f
    {
      '127.0.0.4' => 'Disposable',
      '127.0.0.12' => 'Disposable, Phishing',
      '127.0.0.76' => 'Disposable, Phishing, Abuse',
      '127.0.0.1' => 'Blocked', # an exact match wins over flag decoding
      '127.0.0.2' => '127.0.0.2', # no known flag set, so the code is shown
      '127.0.0.22' => 'Disposable' # unknown flags (2 and 16) are ignored
    }.each do |code, meaning|
      reply = Resolv::DNS::Message.new 1
      reply.add_answer 'example.com.flags.example.dnsbl', 60, Resolv::DNS::Resource::IN::A.new(code)
      res = c.send :decode_response, reply.encode
      assert_equal [meaning], res.map(&:meaning), "meaning of #{code}"
    end
  end

  def test_lists_without_bitmask_show_unknown_codes_as_they_are
    c = DNSBL::Client.new
    c.add_dnsbl 'PLAIN', 'plain.example.dnsbl', 'domain', { '127.0.0.4' => 'Known', '127.0.0.8' => 'Other' }
    c.instance_variable_set :@starttime, Time.now.to_f
    reply = Resolv::DNS::Message.new 1
    reply.add_answer 'example.com.plain.example.dnsbl', 60, Resolv::DNS::Resource::IN::A.new('127.0.0.12')
    assert_equal ['127.0.0.12'], c.send(:decode_response, reply.encode).map(&:meaning)
  end

  def test_spamhaus_error_answers_are_not_described_as_listings
    c = DNSBL::Client.new
    c.instance_variable_set :@starttime, Time.now.to_f
    { 'zen.spamhaus.org' => 'SPAMHAUS', 'cbl.abuseat.org' => 'CBL' }.each do |zone, name|
      reply = Resolv::DNS::Message.new 1
      reply.add_answer "2.0.0.127.#{zone}", 60, Resolv::DNS::Resource::IN::A.new('127.255.255.254')
      res = c.send :decode_response, reply.encode
      assert_equal [name], res.map(&:dnsbl)
      assert_match(/not a listing/, res[0].meaning)
    end
  end

  def test_uribl_blocked_answer_is_not_described_as_a_listing_and_flags_combine
    c = DNSBL::Client.new
    c.instance_variable_set :@starttime, Time.now.to_f
    { '127.0.0.1' => /not a listing/, '127.0.0.14' => /Black list.*Grey list.*Red list/ }.each do |code, expected|
      reply = Resolv::DNS::Message.new 1
      reply.add_answer 'example.com.multi.uribl.com', 60, Resolv::DNS::Resource::IN::A.new(code)
      res = c.send :decode_response, reply.encode
      assert_equal ['URIBL'], res.map(&:dnsbl)
      assert_match expected, res[0].meaning
    end
  end

  def test_spamhaus_dbl_is_a_domain_list_with_its_return_codes
    c = DNSBL::Client.new
    c.instance_variable_set :@starttime, Time.now.to_f
    reply = Resolv::DNS::Message.new 1
    reply.add_answer 'dbltest.com.dbl.spamhaus.org', 60, Resolv::DNS::Resource::IN::A.new('127.0.1.2')
    res = c.send :decode_response, reply.encode
    assert_equal ['SPAMHAUS_DBL'], res.map(&:dnsbl)
    assert_equal ['Spam domain'], res.map(&:meaning)
    assert_equal ['dbltest.com'], res.map(&:item)
  end

  def test_only_ipv6_capable_lists_are_queried_for_ipv6_addresses
    ipv6_domains = queried_domains_for '2001:db8::1'
    config = YAML.safe_load_file File.expand_path('../data/dnsbl.yaml', __dir__)
    expected = config.values.filter_map { |v| v['domain'] if v['type'] == 'ip' && v['ipv6'] && !v['disabled'] }
    refute_empty expected
    assert_equal expected.sort, ipv6_domains.sort
  end

  def test_all_ip_lists_are_queried_for_ipv4_addresses
    config = YAML.safe_load_file File.expand_path('../data/dnsbl.yaml', __dir__)
    expected = config.values.filter_map { |v| v['domain'] if v['type'] == 'ip' && !v['disabled'] }
    assert_equal expected.sort, queried_domains_for('192.0.2.1').sort
  end

  def test_ipv6_items_are_not_treated_as_domains
    assert_empty queried_domains_for('2001:db8::1').grep(/uribl|surbl/)
    assert_empty queried_domains_for('[2001:db8::1]').grep(/uribl|surbl/)
  end

  def test_return_hits_for_ipv6_test_entry
    c = DNSBL::Client.new
    c.nameservers = NAME_SERVERS
    # RFC 5782 section 2.4: IPv6 DNSBLs should list ::FFFF:7F00:2
    res = c.lookup '::ffff:7f00:2'
    assert_operator res.length, :>=, 1, 'expected at least one IPv6-capable list to list the RFC 5782 test entry'
    assert(res.all? { |r| r.item == '::ffff:127.0.0.2' })
  end

  def test_return_no_hits_for_ipv6_documentation_address
    c = DNSBL::Client.new
    c.nameservers = NAME_SERVERS
    # 2001:db8::/32 is reserved for documentation. ::1 is not used because SPFBL flags it as "no mail service"
    res = c.lookup '2001:db8::1'
    puts res if res.length.positive?
    assert_empty res
  end

  def test_normalize_leaves_a_bare_public_suffix_unchanged
    c = DNSBL::Client.new
    # these are in the two-level TLD list, so there is no third label to include
    assert_equal 'co.uk', c.normalize('co.uk')
    assert_equal 'zmail.ru', c.normalize('zmail.ru')
    assert_equal 'example.co.uk', c.normalize('www.example.co.uk')
  end

  def test_normalize_uses_the_longest_matching_public_suffix
    with_suffix_lists %w[co.uk ca.us], %w[k12.ca.us] do |c|
      assert_equal 'example.com', c.normalize('www.example.com')
      assert_equal 'example.co.uk', c.normalize('a.b.example.co.uk')
      assert_equal 'school.k12.ca.us', c.normalize('www.school.k12.ca.us')
      assert_equal 'k12.ca.us', c.normalize('k12.ca.us')
      assert_equal 'city.ca.us', c.normalize('www.city.ca.us')
    end
  end

  def test_normalize_wildcard_suffixes_and_their_exceptions
    # *.ck means every name one label below ck is a suffix, except www.ck which is a normal domain
    with_suffix_lists %w[*.ck !www.ck], %w[*.nom.br !city.nom.br] do |c|
      assert_equal 'example.co.ck', c.normalize('www.example.co.ck')
      assert_equal 'www.example.ck', c.normalize('www.example.ck')
      assert_equal 'www.ck', c.normalize('www.ck')
      assert_equal 'www.ck', c.normalize('mail.www.ck')
      assert_equal 'shop.example.nom.br', c.normalize('www.shop.example.nom.br')
      assert_equal 'city.nom.br', c.normalize('www.city.nom.br')
    end
  end

  def test_normalize_single_label_item
    assert_equal 'localhost', DNSBL::Client.new.normalize('localhost')
  end

  def test_return_results_for_bad_domains
    c = DNSBL::Client.new
    c.nameservers = NAME_SERVERS
    res = c.lookup 'pfizer.viagra.aqybasej.gurdoctor.com'
    assert res.length >= 0
  end

  def test_interpret_project_honeypot_results
    apikey = ENV.fetch 'PHPAPIKEY', nil
    skip 'Project Honeypot API Key Required for this test. Please set PHPAPIKEY.' unless apikey

    config = YAML.safe_load("---
PROJECTHONEYPOT:
  domain: dnsbl.httpbl.org
  type: ip
  apikey: #{apikey}
  decoder: phpot")
    c = DNSBL::Client.new config
    c.nameservers = NAME_SERVERS
    res = c.lookup '127.0.0.1'
    assert_equal 0, res.length
    res = c.lookup '127.1.1.0'
    assert_equal 1, res.length
    assert_equal "#{apikey}.0.1.1.127.dnsbl.httpbl.org", res[0].query
    assert_equal '127.1.1.0', res[0].result
    assert_equal 'type=search engine,engine=AltaVista', res[0].meaning
    res = c.lookup '127.1.1.1'
    assert_equal 1, res.length
    assert_equal "#{apikey}.1.1.1.127", res[0].item
    assert_equal "#{apikey}.1.1.1.127.dnsbl.httpbl.org", res[0].query
    assert_equal '127.1.1.1', res[0].result
    assert_equal 'days=1,score=1,type=suspicious', res[0].meaning
    res = c.lookup '127.1.1.2'
    assert_equal 1, res.length
    assert_equal "#{apikey}.2.1.1.127", res[0].item
    assert_equal "#{apikey}.2.1.1.127.dnsbl.httpbl.org", res[0].query
    assert_equal '127.1.1.2', res[0].result
    assert_equal 'days=1,score=1,type=harvester', res[0].meaning
    res = c.lookup '127.1.1.3'
    assert_equal 1, res.length
    assert_equal "#{apikey}.3.1.1.127", res[0].item
    assert_equal "#{apikey}.3.1.1.127.dnsbl.httpbl.org", res[0].query
    assert_equal '127.1.1.3', res[0].result
    assert_equal 'days=1,score=1,type=suspicious,harvester', res[0].meaning
    res = c.lookup '127.1.1.4'
    assert_equal 1, res.length
    assert_equal "#{apikey}.4.1.1.127", res[0].item
    assert_equal "#{apikey}.4.1.1.127.dnsbl.httpbl.org", res[0].query
    assert_equal '127.1.1.4', res[0].result
    assert_equal 'days=1,score=1,type=comment spammer', res[0].meaning
    res = c.lookup '127.1.1.5'
    assert_equal 1, res.length
    assert_equal "#{apikey}.5.1.1.127", res[0].item
    assert_equal "#{apikey}.5.1.1.127.dnsbl.httpbl.org", res[0].query
    assert_equal '127.1.1.5', res[0].result
    assert_equal 'days=1,score=1,type=suspicious,comment spammer', res[0].meaning
    res = c.lookup '127.1.1.6'
    assert_equal 1, res.length
    assert_equal "#{apikey}.6.1.1.127", res[0].item
    assert_equal "#{apikey}.6.1.1.127.dnsbl.httpbl.org", res[0].query
    assert_equal '127.1.1.6', res[0].result
    assert_equal 'days=1,score=1,type=harvester,comment spammer', res[0].meaning
    res = c.lookup '127.1.1.7'
    assert_equal 1, res.length
    assert_equal "#{apikey}.7.1.1.127", res[0].item
    assert_equal "#{apikey}.7.1.1.127.dnsbl.httpbl.org", res[0].query
    assert_equal '127.1.1.7', res[0].result
    assert_equal 'days=1,score=1,type=suspicious,harvester,comment spammer', res[0].meaning
    res = c.lookup '127.1.10.1'
    assert_equal 1, res.length
    assert_equal "#{apikey}.1.10.1.127", res[0].item
    assert_equal "#{apikey}.1.10.1.127.dnsbl.httpbl.org", res[0].query
    assert_equal '127.1.10.1', res[0].result
    assert_equal 'days=1,score=10,type=suspicious', res[0].meaning
    res = c.lookup '127.1.20.1'
    assert_equal 1, res.length
    assert_equal "#{apikey}.1.20.1.127", res[0].item
    assert_equal "#{apikey}.1.20.1.127.dnsbl.httpbl.org", res[0].query
    assert_equal '127.1.20.1', res[0].result
    assert_equal 'days=1,score=20,type=suspicious', res[0].meaning
    res = c.lookup '127.1.40.1'
    assert_equal 1, res.length
    assert_equal "#{apikey}.1.40.1.127", res[0].item
    assert_equal "#{apikey}.1.40.1.127.dnsbl.httpbl.org", res[0].query
    assert_equal '127.1.40.1', res[0].result
    assert_equal 'days=1,score=40,type=suspicious', res[0].meaning
    res = c.lookup '127.1.80.1'
    assert_equal 1, res.length
    assert_equal "#{apikey}.1.80.1.127", res[0].item
    assert_equal "#{apikey}.1.80.1.127.dnsbl.httpbl.org", res[0].query
    assert_equal '127.1.80.1', res[0].result
    assert_equal 'days=1,score=80,type=suspicious', res[0].meaning
    res = c.lookup '127.10.1.1'
    assert_equal 1, res.length
    assert_equal "#{apikey}.1.1.10.127", res[0].item
    assert_equal "#{apikey}.1.1.10.127.dnsbl.httpbl.org", res[0].query
    assert_equal '127.10.1.1', res[0].result
    assert_equal 'days=10,score=1,type=suspicious', res[0].meaning
    res = c.lookup '127.20.1.1'
    assert_equal 1, res.length
    assert_equal "#{apikey}.1.1.20.127", res[0].item
    assert_equal "#{apikey}.1.1.20.127.dnsbl.httpbl.org", res[0].query
    assert_equal '127.20.1.1', res[0].result
    assert_equal 'days=20,score=1,type=suspicious', res[0].meaning
    res = c.lookup '127.40.1.1'
    assert_equal 1, res.length
    assert_equal "#{apikey}.1.1.40.127", res[0].item
    assert_equal "#{apikey}.1.1.40.127.dnsbl.httpbl.org", res[0].query
    assert_equal '127.40.1.1', res[0].result
    assert_equal 'days=40,score=1,type=suspicious', res[0].meaning
    res = c.lookup '127.80.1.1'
    assert_equal 1, res.length
    assert_equal "#{apikey}.1.1.80.127", res[0].item
    assert_equal "#{apikey}.1.1.80.127.dnsbl.httpbl.org", res[0].query
    assert_equal '127.80.1.1', res[0].result
    assert_equal 'days=80,score=1,type=suspicious', res[0].meaning
    res = c.send :phpot_decoder, '127.0.0.0'
    assert_equal 'type=search engine,engine=undocumented', res
    res = c.send :phpot_decoder, '127.0.1.0'
    assert_equal 'type=search engine,engine=AltaVista', res
    res = c.send :phpot_decoder, '127.0.2.0'
    assert_equal 'type=search engine,engine=Ask', res
    res = c.send :phpot_decoder, '127.0.3.0'
    assert_equal 'type=search engine,engine=Baidu', res
    res = c.send :phpot_decoder, '127.0.4.0'
    assert_equal 'type=search engine,engine=Excite', res
    res = c.send :phpot_decoder, '127.0.5.0'
    assert_equal 'type=search engine,engine=Google', res
    res = c.send :phpot_decoder, '127.0.6.0'
    assert_equal 'type=search engine,engine=Looksmart', res
    res = c.send :phpot_decoder, '127.0.7.0'
    assert_equal 'type=search engine,engine=Lycos', res
    res = c.send :phpot_decoder, '127.0.8.0'
    assert_equal 'type=search engine,engine=MSN', res
    res = c.send :phpot_decoder, '127.0.9.0'
    assert_equal 'type=search engine,engine=Yahoo', res
    res = c.send :phpot_decoder, '127.0.10.0'
    assert_equal 'type=search engine,engine=Cuil', res
    res = c.send :phpot_decoder, '127.0.11.0'
    assert_equal 'type=search engine,engine=InfoSeek', res
    res = c.send :phpot_decoder, '127.0.12.0'
    assert_equal 'type=search engine,engine=Miscellaneous', res
  end

  def test_normalize_domains_to_two_levels_if_it_s_neither_in_two_level_nor_three_level_list
    c = DNSBL::Client.new
    c.nameservers = NAME_SERVERS

    assert_equal 'example.org', c.normalize('example.org')
    assert_equal 'example.org', c.normalize('www.example.org')
    assert_equal 'example.org', c.normalize('foo.bar.baz.example.org')
  end

  def test_normaize_domains_to_three_levels_if_it_s_in_two_level_list
    c = DNSBL::Client.new
    c.nameservers = NAME_SERVERS

    assert_equal 'example.co.uk', c.normalize('example.co.uk')
    assert_equal 'example.co.uk', c.normalize('www.example.co.uk')
    assert_equal 'example.co.uk', c.normalize('foo.bar.baz.example.co.uk')
    assert_equal 'example.blogspot.com', c.normalize('example.blogspot.com')
  end

  def test_normalize_domains_to_four_levels_if_it_s_in_three_level_list
    c = DNSBL::Client.new
    c.nameservers = NAME_SERVERS

    assert_equal 'example.act.edu.au', c.normalize('example.act.edu.au')
    assert_equal 'example.act.edu.au', c.normalize('www.example.act.edu.au')
    assert_equal 'example.act.edu.au', c.normalize('foo.bar.example.act.edu.au')
  end

  private

  # builds a client whose two- and three-level suffix lists come from the given arrays
  def with_suffix_lists(two_level, three_level)
    files = [two_level, three_level].map do |list|
      file = Tempfile.new 'suffixes'
      file.write list.join("\n")
      file.flush
      file
    end
    yield DNSBL::Client.new(YAML.safe_load_file(File.expand_path('../data/dnsbl.yaml', __dir__)), files[0].path, files[1].path)
  ensure
    files&.each(&:close!)
  end

  # sends a lookup to a local UDP socket instead of a real nameserver and returns the DNSBL domains that were queried
  def queried_domains_for(item)
    server = UDPSocket.new
    server.bind '127.0.0.1', 0
    c = DNSBL::Client.new
    c.nameservers = [['127.0.0.1', server.addr[1]]]
    c.instance_variable_set :@timeout, 0.05
    c.lookup item
    queries = []
    begin
      loop { queries << Resolv::DNS::Message.decode(server.recvfrom_nonblock(4096).first) }
    rescue IO::WaitReadable
      nil
    end
    queries.map { |q| q.question.first.first.to_s.sub(/\A(?:(?:\h\.){31}\h|(?:\d+\.){3}\d+)\./, '') }
  ensure
    server&.close
  end
end
