require "dnsbl/client/version"

# DESCRIPTION: is a module that queries dnsbls.  The configuration is in a YAML file.
require 'resolv'
require 'socket'
require 'thread'
require 'yaml'
require 'ipaddr'

# This is a monkeypatch for the built-in Ruby DNS resolver to specify nameservers 
class Resolv::DNS::Config
  # Monkeypatch the nameservers to set a default if there are no defined nameservers
	def nameservers
		return @nameservers if defined?(@nameservers)
		
		lazy_initialize
		if self.respond_to? :nameserver_port
			@nameservers = nameserver_port
		else
			@nameserver ||= ['4.2.2.2','4.2.2.5','8.8.4.4','8.8.8.8','208.67.222.222','208.67.220.220'].sort {rand}
			@nameservers ||= @nameserver.map {|i| [i, 53] }
		end
		@nameservers
	end
end

module DNSBL # :nodoc:
	# DNSBLResult holds the result of a DNSBL lookup
	# dnsbl: name of the DNSBL that returned the answer
	# item: the item queried, an IP or a domain
	# result: the result code, e.g., 127.0.0.2
	# meaning: the mapping of the result code to the meaning from the configuration file
	# timing: the time between starting to send queries to the DNSBLs and when the result from this DNSBL returned
	class DNSBLResult < Struct.new(:dnsbl,:item,:query,:result,:meaning,:timing); end
	
	# Client actually handles the sending of queries to a recursive DNS server and places any replies into DNSBLResults
	class Client
		# initialize a new DNSBL::Client object
		# the config file automatically points to a YAML file containing the list of DNSBLs and their return codes
		# the two-level-tlds file lists most of the two level tlds, needed for hostname to domain normalization
		def initialize(config = YAML.load(File.open(File.expand_path('../../../data', __FILE__)+"/dnsbl.yaml").read),
									 two_level_tldfile = File.expand_path('../../../data', __FILE__)+"/two-level-tlds",
									 three_level_tldfile = File.expand_path('../../../data', __FILE__)+"/three-level-tlds")
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
			config.nameservers.each do |ip,port|
				sock = UDPSocket.new
				sock.connect(ip,port)
				@sockets << sock
				break # let's just the first nameserver in this version of the library
			end
			@socket_index = 0
		end
    
    def timeout=(timeout_seconds)
      @timeout = timeout_seconds
    end
    
    def first_only=(first_only_boolean)
      @first_only = first_only_boolean
    end
    
		# sets the nameservers used for performing DNS lookups in round-robin fashion
		def nameservers=(ns=Resolv::DNS::Config.new.nameservers)
			@sockets.each do |s|
				s.close
			end
			@sockets = []
			ns.each do |ip,port|
				sock = UDPSocket.new
				sock.connect(ip,port)
				@sockets << sock
				break # let's just the first nameserver in this version of the library
			end
			@socket_index = 0
		end
		
		# Converts a hostname to the domain: e.g., www.google.com => google.com, science.somewhere.co.uk => somewhere.co.uk
		def normalize(domain)
			# strip off the protocol (\w{1,20}://), the URI (/), parameters (?), port number (:), and username (.*@)
			# then split into parts via the .
			parts = domain.gsub(/^\w{1,20}:\/\//,'').gsub(/[\/\?\:].*/,'').gsub(/.*?\@/,'').split(/\./)
			# grab the last two parts of the domain
			dom = parts[-2,2].join(".")
			# if the dom is in the two_level_tld list, then use three parts
			if @two_level_tld.index(dom)
				dom = parts[-3,3].join(".")
			end
			if @three_level_tld.index(dom)
				dom = parts[-4,4].join(".")
			end
			dom
		end
		
		# allows the adding of a new DNSBL to the set of configured DNSBLs
		def add_dnsbl(name,domain,type='ip',codes={"0"=>"OK","127.0.0.2"=>"Blacklisted"})
			@dnsbls[name] = codes
			@dnsbls[name]['domain'] = domain
			@dnsbls[name]['type'] = type
		end
		
		# returns a list of DNSBL names currently configured
		def dnsbls
			@dnsbls.keys
		end
		
		# converts an ip or a hostname into the DNS query packet requires to lookup the result
		def _encode_query(item,itemtype,domain,apikey=nil)
			label = nil
			if itemtype == 'ip'
        ip = IPAddr.new(item)
        label = ip.reverse.gsub('.ip6.arpa', '').gsub('.in-addr.arpa', '')
			elsif itemtype == 'domain'
				label = normalize(item)
			end
			lookup = "#{label}.#{domain}"
			if apikey
				lookup = "#{apikey}.#{lookup}"
			end
			txid = lookup.sum
			message = Resolv::DNS::Message.new(txid)
			message.rd = 1
			message.add_question(lookup,Resolv::DNS::Resource::IN::A)
			message.encode
		end
		
		
		# lookup performs the sending of DNS queries for the given items
    # returns an array of DNSBLResult
		def lookup(item)
			# if item is an array, use it, otherwise make it one
			items = item
			if item.is_a? String
				items = [item]
			end
			# place the results in the results array
			results = []
			# for each ip or hostname
			items.each do |item|
				# sent is used to determine when we have all the answers
				sent = 0
				# record the start time
				@starttime = Time.now.to_f
				# determine the type of query
				itemtype = (item =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) ? 'ip' : 'domain'
        itemtype = (item =~ /^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/) ? 'ip' : itemtype

				# for each dnsbl that supports our type, create the DNS query packet and send it
				# rotate across our configured name servers and increment sent
				@dnsbls.each do |name,config|
					next if config['disabled']
					next unless config['type'] == itemtype
					begin
						msg = _encode_query(item,itemtype,config['domain'],config['apikey'])
						@sockets[@socket_index].send(msg,0)
						@socket_index += 1
						@socket_index %= @sockets.length
						sent += 1
					rescue Exception => e
						puts e
						puts e.backtrace.join("\n")
					end
				end
				# while we still expect answers
				while sent > 0
					# wait on the socket for maximally @timeout seconds
					r,_,_ = IO.select(@sockets,nil,nil,@timeout)
					# if we time out, break out of the loop
					break unless r
					# for each reply, decode it and receive results, decrement the pending answers
          first_only = false
					r.each do |s|
						begin
							response = _decode_response(s.recv(4096))
							results += response
						rescue Exception => e
							puts e
							puts e.backtrace.join("\n")
						end
						sent -= 1
            if @first_only
              first_only = true
              break
            end
					end
          if first_only
            break
          end
				end
			end
			results
		end
    
    private
    
		# takes a DNS response and converts it into a DNSBLResult
		def _decode_response(buf)
			reply = Resolv::DNS::Message.decode(buf)
			results = []
			reply.each_answer do |name,ttl,data|
				if name.to_s =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(.+)$/
					ip = [$4,$3,$2,$1].join(".")
					domain = $5
					@dnsbls.each do |dnsblname, config|
						next unless data.is_a? Resolv::DNS::Resource::IN::A
						if domain == config['domain']
							meaning = config[data.address.to_s] || data.address.to_s
							results << DNSBLResult.new(dnsblname, ip, name.to_s, data.address.to_s, meaning, Time.now.to_f - @starttime)
							break
						end
					end
				else
					@dnsbls.each do |dnsblname, config|
						if name.to_s.end_with?(config['domain'])
							meaning = nil
							if config['decoder']
								meaning = self.send(("__"+config['decoder']).to_sym, data.address.to_s)
							elsif config[data.address.to_s]
								meaning = config[data.address.to_s]
							else 
								meaning = data.address.to_s
							end
							results << DNSBLResult.new(dnsblname, name.to_s.gsub("."+config['domain'],''), name.to_s, data.address.to_s, meaning, Time.now.to_f - @starttime)
							break
						end
					end
				end
			end
			results
		end
		
    # decodes the response from Project Honey Pot's service
		def __phpot_decoder(ip)
			octets = ip.split(/\./)
			if octets.length != 4 or octets[0] != "127"
				return "invalid response"
			elsif octets[3] == "0"
				search_engines = ["undocumented", "AltaVista", "Ask", "Baidu", "Excite", "Google", "Looksmart", "Lycos", "MSN", "Yahoo", "Cuil", "InfoSeek", "Miscellaneous"]
				sindex = octets[2].to_i
				if sindex >= search_engines.length
					return "type=search engine,engine=unknown"
				else
					return "type=search engine,engine=#{search_engines[sindex]}"
				end
			else
				days, threatscore, flags = octets[1,3]
				flags = flags.to_i
				types = []
				if (flags & 0x1) == 0x1
					types << "suspicious"
				end
				if (flags & 0x2) == 0x2
					types << "harvester"
				end
				if (flags & 0x4) == 0x4
					types << "comment spammer"
				end
				if (flags & 0xf8) > 0
					types << "reserved"
				end
				type = types.join(",")
				return "days=#{days},score=#{threatscore},type=#{type}"
			end
		end
	end
end
