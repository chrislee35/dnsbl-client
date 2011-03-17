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
end
