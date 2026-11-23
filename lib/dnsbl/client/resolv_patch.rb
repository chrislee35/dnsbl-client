# frozen_string_literal: true

require 'resolv'

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
