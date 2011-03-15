# DESCRIPTION: is a module that queries dnsbls.  The configuration is in a YAML file.
require 'resolv'
require 'socket'
require 'thread'
require 'yaml'

module DNSBL
	class DNSBLResult < Struct.new(:dnsbl,:query,:result,:meaning,:timing); end
	class Client
		def initialize(configfile = File.dirname(__FILE__)+"/dnsbl.yaml")
			@dnsbls = YAML.load(File.open(configfile).read)
			nameservers = Resolv::DNS::Config.new.nameserver_port
			sock = UDPSocket.new
			sock.connect(nameservers[0][0],nameservers[0][1])
			@sockets = [sock]
			@socket_index = 0
		end
		def add_dnsbl(name,domain,type='ip',codes={"0"=>"OK","127.0.0.2"=>"Blacklisted"})
			@dnsbls[name] = codes
			@dnsbls[name]['domain'] = domain
			@dnsbls[name]['type'] = type
		end
		def dnsbls
			@dnsbls.keys
		end
		def _encode_query(ip,domain)
			revip = ip.split(/\./).reverse.join(".")
			lookup = "#{revip}.#{domain}"
			txid = lookup.sum
			message = Resolv::DNS::Message.new(txid)
			message.rd = 1
			message.add_question(lookup,Resolv::DNS::Resource::IN::A)
			message.encode
		end
		def _decode_response(buf)
			reply = Resolv::DNS::Message.decode(buf)
			results = []
			reply.each_answer do |name,ttl,data|
				if name.to_s =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(.+)$/
					ip = [$4,$3,$2,$1].join(".")
					domain = $5
					@dnsbls.each do |dnsblname,config|
						if domain == config['domain']
							meaning = config[data.address.to_s] || data.address.to_s
							results << DNSBLResult.new(dnsblname,name.to_s,data.address.to_s,meaning,Time.now.to_f - @starttime)
							break
						end
					end
				end
			end
			results
		end
		def lookup(ip)
			ips = ip
			if ip.is_a? String
				ips = [ip]
			end
			results = []
			ips.each do |ip|
				sent = 0
				@starttime = Time.now.to_f
				@dnsbls.each do |name,config|
					next unless config['type'] == 'ip'
					msg = _encode_query(ip,config['domain'])
					@sockets[@socket_index].send(msg,0)
					@socket_index += 1
					@socket_index %= @sockets.length
					sent += 1
				end
				while sent > 0
					r,_,_ = IO.select(@sockets,nil,nil,1.5)
					break unless r
					r.each do |s|
						response = _decode_response(s.recv(4096))
						results += response
						sent -= 1
					end
				end
			end
			results
		end
	end
end