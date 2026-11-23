# frozen_string_literal: true

require 'dnsbl/client/version'

# DESCRIPTION: is a module that queries dnsbls.  The configuration is in a YAML file.
require 'resolv'
require 'socket'
require 'yaml'
require 'ipaddr'
require 'dnsbl/client/resolv_patch'

module DNSBL # :nodoc:
  # DNSBLResult holds the result of a DNSBL lookup
  # dnsbl: name of the DNSBL that returned the answer
  # item: the item queried, an IP or a domain
  # result: the result code, e.g., 127.0.0.2
  # meaning: the mapping of the result code to the meaning from the configuration file
  # timing: the time between starting to send queries to the DNSBLs and when the result from this DNSBL returned
  DNSBLResult = Struct.new :dnsbl, :item, :query, :result, :meaning, :timing

  # Client actually handles the sending of queries to a recursive DNS server and places any replies into DNSBLResults
  class Client
    attr_writer :first_only,
                :timeout

    # initialize a new DNSBL::Client object
    # the config file automatically points to a YAML file containing the list of DNSBLs and their return codes
    # the two-level-tlds file lists most of the two level tlds, needed for hostname to domain normalization
    def initialize(config = YAML.safe_load_file("#{File.expand_path '../../data', __dir__}/dnsbl.yaml"),
                   two_level_tldfile = "#{File.expand_path '../../data', __dir__}/two-level-tlds",
                   three_level_tldfile = "#{File.expand_path '../../data', __dir__}/three-level-tlds")
      @dnsbls = config
      @timeout = 1.5
      @first_only = false
      @two_level_tld = []
      @three_level_tld = []
      @two_level_tld = File.readlines(two_level_tldfile).map(&:strip)
      @three_level_tld = File.readlines(three_level_tldfile).map(&:strip)
      @sockets = []
      config = Resolv::DNS::Config.new

      # let's just the first nameserver in this version of the library
      ip, port = config.nameservers.first

      sock = UDPSocket.new
      sock.connect ip, port
      @sockets << sock
      @socket_index = 0
    end

    # sets the nameservers used for performing DNS lookups in round-robin fashion
    def nameservers=(nss = Resolv::DNS::Config.new.nameservers)
      @sockets.each(&:close)
      @sockets = []

      # let's just the first nameserver in this version of the library
      ip, port = nss.first

      sock = UDPSocket.new
      sock.connect ip, port
      @sockets << sock
      @socket_index = 0
    end

    # Converts a hostname to the domain: e.g., www.google.com => google.com, science.somewhere.co.uk => somewhere.co.uk
    # The domain is the longest public suffix plus one more label, using the two- and three-level suffix lists.
    def normalize(domain)
      # strip off the protocol (\w{1,20}://), the URI (/), parameters (?), port number (:), and username (.*@)
      # then split into parts via the .
      parts = domain.gsub(%r{^\w{1,20}://}, '').gsub(%r{[/?:].*}, '').gsub(/.*?@/, '').split('.')
      suffix_length = public_suffix_length parts
      # an item that is itself just a suffix (e.g. co.uk) has no extra label to include and is returned as is
      parts.last(suffix_length + 1).join '.'
    end

    # allows the adding of a new DNSBL to the set of configured DNSBLs
    # set ipv6 to true only if the list answers IPv6 queries, otherwise IPv6 addresses are not sent to it.
    # set bitmask to true if the list combines categories by adding the codes of each (e.g. 127.0.0.12 is both 127.0.0.4 and 127.0.0.8)
    def add_dnsbl(name, domain, type = 'ip', codes = { '0' => 'OK', '127.0.0.2' => 'Blacklisted' }, ipv6: false, bitmask: false)
      @dnsbls[name] = codes
      @dnsbls[name]['domain'] = domain
      @dnsbls[name]['type'] = type
      @dnsbls[name]['ipv6'] = true if ipv6
      @dnsbls[name]['bitmask'] = true if bitmask
    end

    # returns a list of DNSBL names currently configured
    def dnsbls
      @dnsbls.keys
    end

    # lookup performs the sending of DNS queries for the given items
    # returns an array of DNSBLResult
    def lookup(loopup_item)
      # if item is an array, use it, otherwise make it one
      items = Array loopup_item

      # place the results in the results array
      results = []
      # for each ip or hostname
      items.each do |item|
        # sent is used to determine when we have all the answers
        sent = 0
        # record the start time
        @starttime = Time.now.to_f
        # determine the type of query: an IPv4 or IPv6 address is an 'ip' lookup, anything else is a domain
        ip = parse_ip item
        itemtype = ip ? 'ip' : 'domain'

        # for each dnsbl that supports our type, create the DNS query packet and send it
        # rotate across our configured name servers and increment sent
        @dnsbls.each do |name, config|
          next if config['disabled']
          next unless config['type'] == itemtype
          next if ip&.ipv6? && !config['ipv6']

          begin
            msg = encode_query item, itemtype, config['domain'], config['apikey']
            @sockets[@socket_index].send msg, 0
            @socket_index += 1
            @socket_index %= @sockets.length
            sent += 1
          rescue StandardError => e
            puts "error for #{name}: #{e}"
            puts e.backtrace.join("\n")
          end
        end

        # while we still expect answers
        while sent.positive?
          # wait on the socket for maximally @timeout seconds
          r, = IO.select @sockets, nil, nil, @timeout
          # if we time out, break out of the loop
          break unless r

          # for each reply, decode it and receive results, decrement the pending answers
          first_only = false
          r.each do |s|
            begin
              response = decode_response(s.recv(4096))
              results += response
            rescue StandardError => e
              puts e
              puts e.backtrace.join("\n")
            end
            sent -= 1
            if @first_only
              first_only = true
              break
            end
          end
          break if first_only
        end
      end
      results
    end

    private

    # returns how many trailing labels of parts form the longest public suffix (at least one, the TLD).
    # list entries are suffixes (co.uk), wildcards that make every name one label below them a suffix (*.ck),
    # and exceptions to a wildcard (!www.ck), which are themselves registrable so their suffix is one label shorter
    def public_suffix_length(parts)
      [[3, @three_level_tld], [2, @two_level_tld]].each do |count, list|
        next if parts.length < count

        labels = parts.last count
        name = labels.join '.'
        return count - 1 if list.include? "!#{name}"
        return count if list.include?(name) || list.include?("*.#{labels.drop(1).join '.'}")
      end
      1
    end

    # parses an IPv4 or IPv6 address (ignoring surrounding whitespace and any IPv6 zone id), returns nil if the item is not an address
    def parse_ip(item)
      return if item.include? '/'

      IPAddr.new item.strip.sub(/%.*\z/, '')
    rescue IPAddr::Error
      nil
    end

    # converts the nibble-reversed label of an IPv6 query back into a normal IPv6 address
    def ipv6_from_nibbles(label)
      IPAddr.new(label.delete('.').reverse.scan(/.{4}/).join(':')).to_s
    end

    # converts an ip or a hostname into the DNS query packet requires to lookup the result
    def encode_query(item, itemtype, domain, apikey = nil)
      label = case itemtype
              when 'ip'
                parse_ip(item).reverse.gsub('.ip6.arpa', '').gsub('.in-addr.arpa', '')
              when 'domain'
                normalize item
              end

      lookup = "#{label}.#{domain}"
      lookup = "#{apikey}.#{lookup}" if apikey
      txid = lookup.sum
      message = Resolv::DNS::Message.new txid
      message.rd = 1
      message.add_question lookup, Resolv::DNS::Resource::IN::A
      message.encode
    end

    # takes a DNS response and converts it into a DNSBLResult
    def decode_response(buf)
      reply = Resolv::DNS::Message.decode buf
      results = []
      reply.each_answer do |name, _ttl, data|
        # IPv6 nibble labels must be checked first: their leading digits can also look like an IPv4 address
        if name.to_s =~ /^((?:\h\.){31}\h)\.(.+)$/
          results.concat ip_results(name, ipv6_from_nibbles(Regexp.last_match(1)), Regexp.last_match(2), data)
        elsif name.to_s =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(.+)$/
          ip = [Regexp.last_match(4),
                Regexp.last_match(3),
                Regexp.last_match(2),
                Regexp.last_match(1)].join '.'
          results.concat ip_results(name, ip, Regexp.last_match(5), data)
        else
          @dnsbls.each do |dnsblname, config|
            next unless name.to_s.end_with? ".#{config['domain']}"

            meaning = if config['decoder']
                        send :"#{config['decoder']}_decoder", data.address.to_s
                      else
                        meaning_for config, data.address.to_s
                      end

            results << DNSBLResult.new(dnsblname, name.to_s.gsub(".#{config['domain']}", ''),
                                       name.to_s,
                                       data.address.to_s,
                                       meaning,
                                       Time.now.to_f - @starttime)
            break
          end
        end
      end
      results
    end

    # returns the meaning of a result code for a list: an exact match in the list's configuration, or, for a list with the bitmask
    # option (SURBL), the meanings of every flag set in the last octet joined together (127.0.0.12 is the 4 and 8 flags).
    # Falls back to the code itself when nothing is known about it.
    def meaning_for(config, code)
      return config[code] if config[code]
      return code unless config['bitmask']

      prefix, last = code.rpartition('.').values_at 0, 2
      meanings = (1..7).filter_map { |bit| config["#{prefix}.#{1 << bit}"] if last.to_i.anybits? 1 << bit }
      meanings.empty? ? code : meanings.join(', ')
    end

    # builds the result (at most one) for an answer to an IP query against the list that owns the queried domain
    def ip_results(name, ip, domain, data)
      return [] unless data.is_a? Resolv::DNS::Resource::IN::A

      @dnsbls.each do |dnsblname, config|
        next unless domain == config['domain']

        meaning = meaning_for config, data.address.to_s
        return [DNSBLResult.new(dnsblname, ip, name.to_s, data.address.to_s, meaning, Time.now.to_f - @starttime)]
      end
      []
    end

    # decodes the response from Project Honey Pot's service
    def phpot_decoder(ip)
      octets = ip.split '.'
      if octets.length != 4 || octets[0] != '127'
        'invalid response'
      elsif octets[3] == '0'
        search_engines = %w[undocumented AltaVista Ask Baidu Excite Google Looksmart Lycos MSN Yahoo Cuil InfoSeek Miscellaneous]
        sindex = octets[2].to_i
        if sindex >= search_engines.length
          'type=search engine,engine=unknown'
        else
          "type=search engine,engine=#{search_engines[sindex]}"
        end
      else
        days, threatscore, flags = octets[1, 3]
        flags = flags.to_i
        types = []
        types << 'suspicious' if flags.allbits? 0x1
        types << 'harvester' if flags.allbits? 0x2
        types << 'comment spammer' if flags.allbits? 0x4
        types << 'reserved' if flags.anybits? 0xf8
        type = types.join ','
        "days=#{days},score=#{threatscore},type=#{type}"
      end
    end
  end
end
