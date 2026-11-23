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

# IPv6 addresses (any notation: compressed, expanded, bracketed, or with a zone id)
c.lookup('2607:f8b0:4004:805::2004')

# domain names
c.lookup('example.com')

# add your own list: name, DNS zone, type ('ip' or 'domain'), a map of result codes to meanings,
# and ipv6: true if the list answers IPv6 queries
c.add_dnsbl('superdnsbl', 'super.dnsbl.com', 'ip', { '0' => 'OK', '127.0.0.2' => 'Blacklisted' }, ipv6: true)
puts c.dnsbls.join(' ')
```

A command line client is installed as well. It takes addresses as arguments, or one per line on standard input:

    $ dnsbl-client 127.0.0.2

### IPv6

IPv6 addresses are queried as RFC 5782 describes: the 32 nibbles of the expanded address, reversed and dot-separated, are prepended to the
list's zone. Most DNSBLs are IPv4-only and would answer "not listed" for every IPv6 address, which is a false negative, so IPv6 addresses are
only sent to lists marked `ipv6: true` in [data/dnsbl.yaml](data/dnsbl.yaml). A list was marked only after it listed the RFC 5782 IPv6 test
entry `::FFFF:7F00:2` and did not list `2001:db8::1`. If you know that another list supports IPv6, set `ipv6: true` for it in your
configuration.

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
(should be listed) and `127.0.0.1` (should not be), and `::FFFF:7F00:2` as the IPv6 equivalent of `127.0.0.2`.

## Development

    $ bundle install
    $ bundle exec rake test       # run the tests
    $ bundle exec rubocop         # lint
    $ bundle exec rake rdoc       # build the API documentation into html/
    $ bundle exec rake update_tlds  # refresh data/two-level-tlds and data/three-level-tlds from the Public Suffix List

The two- and three-level suffix lists in `data/` are used to reduce a hostname to the domain that domain blacklists are queried for
(`www.example.co.uk` becomes `example.co.uk`). `rake update_tlds` downloads the current [Public Suffix List](https://publicsuffix.org/)
and regenerates both files; pass a local copy with `rake "update_tlds[path/to/public_suffix_list.dat]"`.

Some tests query live DNS blacklists, so they depend on the network and on those services' current behavior. The Project Honeypot test
is skipped unless `PHPAPIKEY` is set.

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

<a href='mailto:github@chrislee[dot]dhs[dot]org[stop here]xxx'><img src='http://chrisleephd.us/images/github-email.png?dnsbl-client'></a>
