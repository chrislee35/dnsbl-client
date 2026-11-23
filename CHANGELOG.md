# Changelog

## 2.0.0 - 2026-11-23

### Breaking changes

- Requires Ruby 3.2 or newer (was 2.7).
- Eight DNSBLs that no longer answer were removed from the default list: `VIRBL`, `SORBS`, `NJABL`, `MAILSHELL`, `DRONE_ABUSE_CH`,
  `HTTPBL_ABUSE_CH`, `SPAM_ABUSE_CH` and `NOMOREFUN`.
- The meanings reported for SPFBL and SURBL result codes changed to match those lists' current documentation. SURBL answers are now
  described by category (`127.0.0.12` is "Disposable email domain (DM), Phishing site (PH)") instead of by the old data sources.
- Domain names are reduced to the registrable domain using the longest matching public suffix, so some results of `normalize` differ
  (for example `www.example.pg` and `a.b.bo.telemark.no` are now handled correctly).
- A string that is not a valid IP address, such as `999.1.1.1`, is treated as a domain name. It used to be treated as an IP address and
  failed with an error.
- The gem no longer ships the `test/` directory, and snap packaging was dropped.

### Added

- IPv6 support (issue #8). IPv6 addresses (compressed, expanded, bracketed, or with a zone id) are queried in the RFC 5782 nibble format
  and the result reports the normal address. Lists must opt in with `ipv6: true` (also an `add_dnsbl` keyword), because most DNSBLs are
  IPv4-only and would answer "not listed" for every IPv6 address. Enabled for SPAMCOP, DRONEBL, BARRACUDA, UCEPROTECT1, UCEPROTECT2,
  WHITELIST, BACKSCATTERER, SPFBL, SPAMHAUS, CBL, NORDSPAM, ZAPBL, S5H, JUSTSPAM, MAILSPIKE_Z and PSBL, each of which listed the RFC 5782
  IPv6 test entry `::FFFF:7F00:2`.
- New DNSBLs: `NORDSPAM`, `NORDSPAM_DBL` (domains), `ZAPBL`, `S5H`, `JUSTSPAM`, `MAILSPIKE_Z`, `PSBL`, `SEM_BLACK` and `SPAMHAUS_DBL` (domains).
- Lists with a `bitmask: true` option (SURBL, URIBL; also an `add_dnsbl` keyword) report the meanings of every flag set in a combined
  result code.
- Error answers from Spamhaus (`127.255.255.252`, `.254`, `.255`) and URIBL's blocked-query answers (`127.0.0.1`, `127.0.0.255`) now have
  meanings that say they are not listings.
- `rake update_tlds` regenerates the two- and three-level suffix lists from the Public Suffix List.
- API documentation is published to GitHub Pages: <https://chrislee35.github.io/dnsbl-client/>.
- `CHANGELOG.md` and a `.mailmap`.

### Fixed

- Answers from a domain list were matched on the end of the zone name, so a list such as `dbl.example.com` could be credited to
  `bl.example.com`. Zones are now matched on a label boundary.
- `normalize` raised `NoMethodError` for an item that is itself a public suffix (`co.uk`, `zmail.ru`) and for single-label items.
- Wildcard (`*.ck`) and exception (`!www.ck`) rules from the Public Suffix List are now honored.
- The error message printed when building a query now includes the exception message.

### Changed

- `data/two-level-tlds` and `data/three-level-tlds` were regenerated from the Public Suffix List (2026-11-21). Suffixes that were in the
  wrong file moved, and internationalized names are punycode.
- The `Resolv::DNS::Config` default-nameserver patch moved to `lib/dnsbl/client/resolv_patch.rb`.
- `data/dnsbl.yaml` and the README were refreshed; the SPFBL meanings follow its current documentation.
- CI runs on Ruby 3.2, 3.3, 3.4 and head with current GitHub Actions, and RuboCop targets Ruby 3.2.

## 1.1.1

Last release before this changelog was kept.
