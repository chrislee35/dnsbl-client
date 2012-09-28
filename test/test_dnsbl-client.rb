require 'helper'
require 'pp'

class TestDnsblClient < Test::Unit::TestCase
	should "return no hits for 127.0.0.255" do
		c = DNSBL::Client.new
		res = c.lookup("127.0.0.255")
		assert_equal(0,res.length)
	end
	should "return all lists for 127.0.0.2" do
		c = DNSBL::Client.new
		res = c.lookup("127.0.0.2")
		assert(res.length >= c.dnsbls.length)
	end
	should "return results for bad domains" do
		c = DNSBL::Client.new
		res = c.lookup("pfizer.viagra.aqybasej.gurdoctor.com")
		assert(res.length >= 0)
	end
	should "interpret project honeypot results" do
		raise "Project Honeypot API Key Required.  Please set PHPAPIKEY." unless ENV['PHPAPIKEY']
		apikey = ENV['PHPAPIKEY']
		config = YAML.load("---
PROJECTHONEYPOT:
  domain: dnsbl.httpbl.org
  type: ip
  apikey: #{apikey}
  decoder: phpot_decoder")
		c = DNSBL::Client.new(config)
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

	should "normalize domains to two levels if it's neither in two-level nor three-level list" do
		c = DNSBL::Client.new

		assert_equal("example.org", c.normalize("example.org"))
		assert_equal("example.org", c.normalize("www.example.org"))
		assert_equal("example.org", c.normalize("foo.bar.baz.example.org"))
	end

	should "normaize domains to three levels if it's in two-level list" do
		c = DNSBL::Client.new

		assert_equal("example.co.uk", c.normalize("example.co.uk"))
		assert_equal("example.co.uk", c.normalize("www.example.co.uk"))
		assert_equal("example.co.uk", c.normalize("foo.bar.baz.example.co.uk"))
		assert_equal("example.blogspot.com", c.normalize("example.blogspot.com"))
	end

	should "normalize domains to four levels if it's in three-level list" do
		c = DNSBL::Client.new

		assert_equal("example.act.edu.au", c.normalize("example.act.edu.au"))
		assert_equal("example.act.edu.au", c.normalize("www.example.act.edu.au"))
		assert_equal("example.act.edu.au", c.normalize("foo.bar.example.act.edu.au"))
	end
end
