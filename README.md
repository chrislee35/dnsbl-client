# DNSBL::Client

dnsbl-client queries DNS Blacklists for listings. Currently this only does IP lookups, but the next version will handle domains.

## Installation

Add this line to your application's Gemfile:

    gem 'dnsbl-client'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install dnsbl-client

## Usage

	require "dnsbl-client"
	c = DNSBL::Client.new 
	c.lookup("203.150.14.85")
	=> [#<struct DNSBL::DNSBLResult dnsbl="UCEPROTECT1", query="85.14.150.203.dnsbl-1.uceprotect.net", result="127.0.0.2", meaning="Blacklisted", timing=0.0247988700866699>, #<struct DNSBL::DNSBLResult dnsbl="BARRACUDA", query="85.14.150.203.b.barracudacentral.org", result="127.0.0.2", meaning="Listed", timing=0.0266849994659424>]
	
	c.add_dnsbl("superdnsbl","super.dnsbl.com",'ip',{"0"=>"OK","127.0.0.2"=>"Blacklisted"})
	puts c.dnsbls.join(" ")

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

<a href='mailto:github@chrislee[dot]dhs[dot]org[stop here]xxx'><img src='http://chrisleephd.us/images/github-email.png?dnsbl-client'></a>