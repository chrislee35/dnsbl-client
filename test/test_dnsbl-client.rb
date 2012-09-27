require 'helper'

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

  should "allow concat in list domain" do
    c = DNSBL::Client.new

    result = c._encode_query('127.0.0.1', 'ip', 'test.%s.example.org')
    assert_equal(result, "\b3\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04test\x011\x010\x010\x03127\aexample\x03org\x00\x00\x01\x00\x01")
  end
end
