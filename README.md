# DNSBL::Client

dnsbl-client queries DNS blacklists (DNSBLs) for listings. It looks up both IP addresses and domain names across many lists in parallel and
returns what each list answered, with a human-readable meaning for each result code.

API documentation: <https://chrislee35.github.io/dnsbl-client/>

## Requirements

Ruby 3.2 or newer.

## Installation

Add this line to your application's Gemfile:

    gem 'dnsbl-client'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install dnsbl-client

## Usage

```ruby
require 'dnsbl/client'
c = DNSBL::Client.new

# IP addresses
c.lookup('127.0.0.2')
# => [#<struct DNSBL::DNSBLResult dnsbl="BARRACUDA", item="127.0.0.2", query="2.0.0.127.b.barracudacentral.org",
#      result="127.0.0.2", meaning="Listed", timing=0.026>, ...]

# domain names
c.lookup('example.com')

# add your own list: name, DNS zone, type ('ip' or 'domain'), and a map of result codes to meanings
c.add_dnsbl('superdnsbl', 'super.dnsbl.com', 'ip', { '0' => 'OK', '127.0.0.2' => 'Blacklisted' })
puts c.dnsbls.join(' ')
```

A command line client is installed as well. It takes addresses as arguments, or one per line on standard input:

    $ dnsbl-client 127.0.0.2

### Choosing a resolver

Several lists (Spamhaus ZEN, CBL, URIBL, SURBL and others) refuse queries that arrive through large public resolvers, and answer with a
special code instead of a real result. For example, URIBL answers `127.0.0.1` and Spamhaus answers `127.255.255.254`; neither means the
item is listed. For reliable results, query through your own recursive resolver:

```ruby
c.nameservers = [['192.0.2.53', 53]]
```

### Return codes

Result codes mean different things on different lists, and not every answer is a spam verdict. For instance, `dnsbl.spfbl.net` returns
`127.0.0.4` for addresses that do not appear to run a mail service (such as NAT routers and residential connections). The meaning for each
code is in [data/dnsbl.yaml](data/dnsbl.yaml). RFC 5782 describes common DNSBL conventions, including the test entries `127.0.0.2`
(should be listed) and `127.0.0.1` (should not be).

## Development

    $ bundle install
    $ bundle exec rake test       # run the tests
    $ bundle exec rubocop         # lint
    $ bundle exec rake rdoc       # build the API documentation into html/

Some tests query live DNS blacklists, so they depend on the network and on those services' current behavior. The Project Honeypot test
is skipped unless `PHPAPIKEY` is set.

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

<a href='mailto:github@chrislee[dot]dhs[dot]org[stop here]xxx'><img src='http://chrisleephd.us/images/github-email.png?dnsbl-client'></a>
