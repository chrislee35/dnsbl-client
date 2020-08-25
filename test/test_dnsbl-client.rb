unless Kernel.respond_to?(:require_relative)
  module Kernel
    def require_relative(path)
      require File.join(File.dirname(caller[0]), path.to_str)
    end
  end
end

require_relative 'helper'

$nameservers = [['4.2.2.2',53]]

class TestDNSBLClient < Minitest::Test
  def test_return_no_hits_for_0_0_0_254
    c = DNSBL::Client.new
    c.nameservers = $nameservers
    # for some reason DRONEBL returns 127.0.0.255 when queried for 127.0.0.255, so I'll use 127.0.0.254
    # spfbl started returning 127.0.0.254 for 127.0.0.254, so I'll try 0.0.0.254
    res = c.lookup("0.0.0.254")
    if res.length > 0
      puts(res)
    end
    assert_equal(0,res.length)
  end
  def test_return_all_lists_for_127_0_0_2
    # this test doesn't work anymore
    #c = DNSBL::Client.new
    #c.nameservers = $nameservers
    #res = c.lookup("127.0.0.2")
    #puts res
    #puts c.dnsbls
    #assert(res.length >= c.dnsbls.length)
  end
  def test_return_results_for_bad_domains
    c = DNSBL::Client.new
    c.nameservers = $nameservers
    res = c.lookup("pfizer.viagra.aqybasej.gurdoctor.com")
    assert(res.length >= 0)
  end
  def test_interpret_project_honeypot_results
    refute_nil(ENV['PHPAPIKEY'], "Project Honeypot API Key Required.  Please set PHPAPIKEY.")
    apikey = ENV['PHPAPIKEY']
    config = YAML.load("---
PROJECTHONEYPOT:
  domain: dnsbl.httpbl.org
  type: ip
  apikey: #{apikey}
  decoder: phpot_decoder")
    c = DNSBL::Client.new(config)
    c.nameservers = $nameservers
    res = c.lookup("127.0.0.1")
    assert_equal(0,res.length)
    res = c.lookup("127.1.1.0")
    assert_equal(1,res.length)
    assert_equal("#{apikey}.0.1.1.127.dnsbl.httpbl.org",res[0].query)
    assert_equal("127.1.1.0",res[0].result)
    assert_equal("type=search engine,engine=AltaVista",res[0].meaning)
    res = c.lookup("127.1.1.1")
    assert_equal(1,res.length)
    assert_equal("#{apikey}.1.1.1.127",res[0].item)
    assert_equal("#{apikey}.1.1.1.127.dnsbl.httpbl.org",res[0].query)
    assert_equal("127.1.1.1",res[0].result)
    assert_equal("days=1,score=1,type=suspicious",res[0].meaning)
    res = c.lookup("127.1.1.2")
    assert_equal(1,res.length)
    assert_equal("#{apikey}.2.1.1.127",res[0].item)
    assert_equal("#{apikey}.2.1.1.127.dnsbl.httpbl.org",res[0].query)
    assert_equal("127.1.1.2",res[0].result)
    assert_equal("days=1,score=1,type=harvester",res[0].meaning)
    res = c.lookup("127.1.1.3")
    assert_equal(1,res.length)
    assert_equal("#{apikey}.3.1.1.127",res[0].item)
    assert_equal("#{apikey}.3.1.1.127.dnsbl.httpbl.org",res[0].query)
    assert_equal("127.1.1.3",res[0].result)
    assert_equal("days=1,score=1,type=suspicious,harvester",res[0].meaning)
    res = c.lookup("127.1.1.4")
    assert_equal(1,res.length)
    assert_equal("#{apikey}.4.1.1.127",res[0].item)
    assert_equal("#{apikey}.4.1.1.127.dnsbl.httpbl.org",res[0].query)
    assert_equal("127.1.1.4",res[0].result)
    assert_equal("days=1,score=1,type=comment spammer",res[0].meaning)
    res = c.lookup("127.1.1.5")
    assert_equal(1,res.length)
    assert_equal("#{apikey}.5.1.1.127",res[0].item)
    assert_equal("#{apikey}.5.1.1.127.dnsbl.httpbl.org",res[0].query)
    assert_equal("127.1.1.5",res[0].result)
    assert_equal("days=1,score=1,type=suspicious,comment spammer",res[0].meaning)
    res = c.lookup("127.1.1.6")
    assert_equal(1,res.length)
    assert_equal("#{apikey}.6.1.1.127",res[0].item)
    assert_equal("#{apikey}.6.1.1.127.dnsbl.httpbl.org",res[0].query)
    assert_equal("127.1.1.6",res[0].result)
    assert_equal("days=1,score=1,type=harvester,comment spammer",res[0].meaning)
    res = c.lookup("127.1.1.7")
    assert_equal(1,res.length)
    assert_equal("#{apikey}.7.1.1.127",res[0].item)
    assert_equal("#{apikey}.7.1.1.127.dnsbl.httpbl.org",res[0].query)
    assert_equal("127.1.1.7",res[0].result)
    assert_equal("days=1,score=1,type=suspicious,harvester,comment spammer",res[0].meaning)
    res = c.lookup("127.1.10.1")
    assert_equal(1,res.length)
    assert_equal("#{apikey}.1.10.1.127",res[0].item)
    assert_equal("#{apikey}.1.10.1.127.dnsbl.httpbl.org",res[0].query)
    assert_equal("127.1.10.1",res[0].result)
    assert_equal("days=1,score=10,type=suspicious",res[0].meaning)
    res = c.lookup("127.1.20.1")
    assert_equal(1,res.length)
    assert_equal("#{apikey}.1.20.1.127",res[0].item)
    assert_equal("#{apikey}.1.20.1.127.dnsbl.httpbl.org",res[0].query)
    assert_equal("127.1.20.1",res[0].result)
    assert_equal("days=1,score=20,type=suspicious",res[0].meaning)
    res = c.lookup("127.1.40.1")
    assert_equal(1,res.length)
    assert_equal("#{apikey}.1.40.1.127",res[0].item)
    assert_equal("#{apikey}.1.40.1.127.dnsbl.httpbl.org",res[0].query)
    assert_equal("127.1.40.1",res[0].result)
    assert_equal("days=1,score=40,type=suspicious",res[0].meaning)
    res = c.lookup("127.1.80.1")
    assert_equal(1,res.length)
    assert_equal("#{apikey}.1.80.1.127",res[0].item)
    assert_equal("#{apikey}.1.80.1.127.dnsbl.httpbl.org",res[0].query)
    assert_equal("127.1.80.1",res[0].result)
    assert_equal("days=1,score=80,type=suspicious",res[0].meaning)
    res = c.lookup("127.10.1.1")
    assert_equal(1,res.length)
    assert_equal("#{apikey}.1.1.10.127",res[0].item)
    assert_equal("#{apikey}.1.1.10.127.dnsbl.httpbl.org",res[0].query)
    assert_equal("127.10.1.1",res[0].result)
    assert_equal("days=10,score=1,type=suspicious",res[0].meaning)
    res = c.lookup("127.20.1.1")
    assert_equal(1,res.length)
    assert_equal("#{apikey}.1.1.20.127",res[0].item)
    assert_equal("#{apikey}.1.1.20.127.dnsbl.httpbl.org",res[0].query)
    assert_equal("127.20.1.1",res[0].result)
    assert_equal("days=20,score=1,type=suspicious",res[0].meaning)
    res = c.lookup("127.40.1.1")
    assert_equal(1,res.length)
    assert_equal("#{apikey}.1.1.40.127",res[0].item)
    assert_equal("#{apikey}.1.1.40.127.dnsbl.httpbl.org",res[0].query)
    assert_equal("127.40.1.1",res[0].result)
    assert_equal("days=40,score=1,type=suspicious",res[0].meaning)
    res = c.lookup("127.80.1.1")
    assert_equal(1,res.length)
    assert_equal("#{apikey}.1.1.80.127",res[0].item)
    assert_equal("#{apikey}.1.1.80.127.dnsbl.httpbl.org",res[0].query)
    assert_equal("127.80.1.1", res[0].result)
    assert_equal("days=80,score=1,type=suspicious",res[0].meaning)
    res = c.__phpot_decoder("127.0.0.0")
    assert_equal("type=search engine,engine=undocumented",res)
    res = c.__phpot_decoder("127.0.1.0")
    assert_equal("type=search engine,engine=AltaVista",res)
    res = c.__phpot_decoder("127.0.2.0")
    assert_equal("type=search engine,engine=Ask",res)
    res = c.__phpot_decoder("127.0.3.0")
    assert_equal("type=search engine,engine=Baidu",res)
    res = c.__phpot_decoder("127.0.4.0")
    assert_equal("type=search engine,engine=Excite",res)
    res = c.__phpot_decoder("127.0.5.0")
    assert_equal("type=search engine,engine=Google",res)
    res = c.__phpot_decoder("127.0.6.0")
    assert_equal("type=search engine,engine=Looksmart",res)
    res = c.__phpot_decoder("127.0.7.0")
    assert_equal("type=search engine,engine=Lycos",res)
    res = c.__phpot_decoder("127.0.8.0")
    assert_equal("type=search engine,engine=MSN",res)
    res = c.__phpot_decoder("127.0.9.0")
    assert_equal("type=search engine,engine=Yahoo",res)
    res = c.__phpot_decoder("127.0.10.0")
    assert_equal("type=search engine,engine=Cuil",res)
    res = c.__phpot_decoder("127.0.11.0")
    assert_equal("type=search engine,engine=InfoSeek",res)
    res = c.__phpot_decoder("127.0.12.0")
    assert_equal("type=search engine,engine=Miscellaneous",res)
  end

  def test_normalize_domains_to_two_levels_if_it_s_neither_in_two_level_nor_three_level_list
    c = DNSBL::Client.new
    c.nameservers = $nameservers

    assert_equal("example.org", c.normalize("example.org"))
    assert_equal("example.org", c.normalize("www.example.org"))
    assert_equal("example.org", c.normalize("foo.bar.baz.example.org"))
  end

  def test_normaize_domains_to_three_levels_if_it_s_in_two_level_list
    c = DNSBL::Client.new
    c.nameservers = $nameservers

    assert_equal("example.co.uk", c.normalize("example.co.uk"))
    assert_equal("example.co.uk", c.normalize("www.example.co.uk"))
    assert_equal("example.co.uk", c.normalize("foo.bar.baz.example.co.uk"))
    assert_equal("example.blogspot.com", c.normalize("example.blogspot.com"))
  end

  def test_normalize_domains_to_four_levels_if_it_s_in_three_level_list
    c = DNSBL::Client.new
    c.nameservers = $nameservers

    assert_equal("example.act.edu.au", c.normalize("example.act.edu.au"))
    assert_equal("example.act.edu.au", c.normalize("www.example.act.edu.au"))
    assert_equal("example.act.edu.au", c.normalize("foo.bar.example.act.edu.au"))
  end
end
