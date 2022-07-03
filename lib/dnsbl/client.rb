# frozen_string_literal: true

require 'dnsbl/client/version'

# DESCRIPTION: is a module that queries dnsbls.  The configuration is in a YAML file.
require 'resolv'
require 'socket'
require 'yaml'
require 'ipaddr'

# This is a monkeypatch for the built-in Ruby DNS resolver to specify nameservers
class Resolv
  class DNS
    class Config
      # Monkeypatch the nameservers to set a default if there are no defined nameservers
      def nameservers
        return @nameservers if defined?(@nameservers)

        lazy_initialize
        if respond_to? :nameserver_port
          @nameservers = nameserver_port
        else
          @nameserver ||= ['4.2.2.2',
                           '4.2.2.5',
                           '8.8.4.4',
                           '8.8.8.8',
                           '208.67.222.222',
                           '208.67.220.220'].shuffle
          @nameservers ||= @nameserver.map { |i| [i, 53] }
        end
        @nameservers
      end
    end
  end
end

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
    def initialize(config = YAML.safe_load(File.read("#{File.expand_path '../../data', __dir__}/dnsbl.yaml")),
                   two_level_tldfile = "#{File.expand_path '../../data', __dir__}/two-level-tlds",
                   three_level_tldfile = "#{File.expand_path '../../data', __dir__}/three-level-tlds")
      @dnsbls = config
      @timeout = 1.5
      @first_only = false
      @two_level_tld = []
      @three_level_tld = []
      File.open(two_level_tldfile).readlines.each do |l|
        @two_level_tld << l.strip
      end
      File.open(three_level_tldfile).readlines.each do |l|
        @three_level_tld << l.strip
      end
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
    def normalize(domain)
      # strip off the protocol (\w{1,20}://), the URI (/), parameters (?), port number (:), and username (.*@)
      # then split into parts via the .
      parts = domain.gsub(%r{^\w{1,20}://}, '').gsub(%r{[/?:].*}, '').gsub(/.*?@/, '').split('.')
      # grab the last two parts of the domain
      dom = parts[-2, 2].join '.'
      # if the dom is in the two_level_tld list, then use three parts
      dom = parts[-3, 3].join '.' if @two_level_tld.index dom
      dom = parts[-4, 4].join '.' if @three_level_tld.index dom
      dom
    end

    # allows the adding of a new DNSBL to the set of configured DNSBLs
    def add_dnsbl(name, domain, type = 'ip', codes = { '0' => 'OK', '127.0.0.2' => 'Blacklisted' })
      @dnsbls[name] = codes
      @dnsbls[name]['domain'] = domain
      @dnsbls[name]['type'] = type
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
        # determine the type of query
        itemtype = item.match?(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) ? 'ip' : 'domain'
        if item.match?(/^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/) # rubocop: disable Layout/LineLength
          itemtype = 'ip'
        end

        # for each dnsbl that supports our type, create the DNS query packet and send it
        # rotate across our configured name servers and increment sent
        @dnsbls.each do |name, config|
          next if config['disabled']
          next unless config['type'] == itemtype

          begin
            msg = encode_query item, itemtype, config['domain'], config['apikey']
            @sockets[@socket_index].send msg, 0
            @socket_index += 1
            @socket_index %= @sockets.length
            sent += 1
          rescue StandardError => e
            puts "error for #{name}: e"
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

    # converts an ip or a hostname into the DNS query packet requires to lookup the result
    def encode_query(item, itemtype, domain, apikey = nil)
      label = case itemtype
              when 'ip'
                ip = IPAddr.new item
                ip.reverse.gsub('.ip6.arpa', '').gsub('.in-addr.arpa', '')
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
        if name.to_s =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(.+)$/
          ip = [Regexp.last_match(4),
                Regexp.last_match(3),
                Regexp.last_match(2),
                Regexp.last_match(1)].join '.'
          domain = Regexp.last_match 5
          @dnsbls.each do |dnsblname, config|
            next unless data.is_a? Resolv::DNS::Resource::IN::A
            next unless domain == config['domain']

            meaning = config[data.address.to_s] || data.address.to_s
            results << DNSBLResult.new(dnsblname, ip, name.to_s, data.address.to_s, meaning, Time.now.to_f - @starttime)
            break
          end
        else
          @dnsbls.each do |dnsblname, config|
            next unless name.to_s.end_with? config['domain']

            meaning = if config['decoder']
                        send "#{config['decoder']}_decoder".to_sym, data.address.to_s
                      elsif config[data.address.to_s]
                        config[data.address.to_s]
                      else
                        data.address.to_s
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
        types << 'suspicious' if (flags & 0x1) == 0x1
        types << 'harvester' if (flags & 0x2) == 0x2
        types << 'comment spammer' if (flags & 0x4) == 0x4
        types << 'reserved' if (flags & 0xf8).positive?
        type = types.join ','
        "days=#{days},score=#{threatscore},type=#{type}"
      end
    end
  end
end
