# DESCRIPTION: is a module that queries dnsbls.  The configuration is in a YAML file.
require 'resolv'
require 'socket'
require 'thread'
require 'yaml'

class Resolv::DNS::Config
	def nameservers
		return @nameservers if @namservers
		
		lazy_initialize
		if self.respond_to? :nameserver_port
			@nameservers = nameserver_port
		else
			@nameserver ||= ['4.2.2.2','4.2.2.5','8.8.4.4','8.8.8.8','208.67.222.222','208.67.220.220']
			@nameservers ||= @nameserver.map {|i| [i, 53] }
		end
		@nameservers
	end
end

module DNSBL
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
		def initialize(configfile = File.dirname(__FILE__)+"/dnsbl.yaml", 
									 two_level_tldfile = File.dirname(__FILE__)+"/two-level-tlds",
									 three_level_tldfile = File.dirname(__FILE__)+"/three-level-tlds")
			@dnsbls = YAML.load(File.open(configfile).read)
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
		def _encode_query(item,itemtype,domain)
			label = nil
			if itemtype == 'ip'
				label = item.split(/\./).reverse.join(".")
			elsif itemtype == 'domain'
				label = normalize(item)
			end
			lookup = "#{label}.#{domain}"
			txid = lookup.sum
			message = Resolv::DNS::Message.new(txid)
			message.rd = 1
			message.add_question(lookup,Resolv::DNS::Resource::IN::A)
			message.encode
		end
		
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
							meaning = config[data.address.to_s] || data.address.to_s
							results << DNSBLResult.new(dnsblname, name.to_s.gsub("."+config['domain'],''), name.to_s, data.address.to_s, meaning, Time.now.to_f - @starttime)
							break
						end
					end
				end
			end
			results
		end
		
		# the main method of this class, lookup performs the sending of DNS queries for the items
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
				# for each dnsbl that supports our type, create the DNS query packet and send it
				# rotate across our configured name servers and increment sent
				@dnsbls.each do |name,config|
					next unless config['type'] == itemtype
					begin
						msg = _encode_query(item,itemtype,config['domain'])
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
					# wait on the socket for maximally 1.5 seconds
					r,_,_ = IO.select(@sockets,nil,nil,1.5)
					# if we time out, break out of the loop
					break unless r
					# for each reply, decode it and receive results, decrement the pending answers
					r.each do |s|
						begin
							response = _decode_response(s.recv(4096))
							results += response
						rescue Exception => e
							puts e
							puts e.backtrace.join("\n")
						end
						sent -= 1
					end
				end
			end
			results
		end
	end
end
