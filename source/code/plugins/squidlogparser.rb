# Linux Squid Proxy Log Monitoring Solution for Operations Management Suite
# Developed by Alessandro Cardoso, v 1.0, Feb 2017
# Microsoft Enterprise Services Delivery
# Asia Pacific, Greater China, India & Japan 
# 
# Library for Squid to allow capture Squid statistics
#
module Fluent

#### Log Parser lib - access.log

  class SquidLogParser < Parser
    # Register this parser
    Plugin.register_parser('SquidLogParser', self)

    def initialize
      require 'fluent/parser'
      super
      @parser = SquidLogParserLib.new()
    end

    # This method is called after config_params have read configuration parameters
    def configure(conf)
      super
    end

    def parse(text)
      time, record = @parser.parse(text)
      yield time, record
    end
  end

#### Log Parser lib - access.log

  class SquidLogParserLib
    require 'date'
    require 'etc'
    require_relative 'oms_common'
    require 'fluent/parser'

    REGEX =/(?<eventtime>(\d+))\.\d+\s+(?<duration>(\d+))\s+(?<sourceip>(\d+\.\d+\.\d+\.\d+))\s+(?<cache>(\w+))\/(?<status>(\d+))\s+(?<bytes>(\d+)\s+)(?<response>(\w+)\s+)(?<url>([^\s]+))\s+(?<user>(\w+|\-))\s+(?<method>(\S+.\S+))/

    def parse(line)

      data = {}
      time = Time.now.to_f

      begin
        REGEX.match(line) { |match|
          data['Host'] = OMS::Common.get_hostname

          timestamp = Time.at( match['eventtime'].to_i() )
          data['EventTime'] = OMS::Common.format_time(timestamp)
          data['EventDate'] = timestamp.strftime( '%Y-%m-%d' )
          data['Duration'] = match['duration'].to_i()
          data['SourceIP'] = match['sourceip']
          data['cache'] = match['cache']
          data['status'] = match['status']
          data['bytes'] = match['bytes'].to_i()
          data['httpresponse'] = match['response']
          data['bytes'] = match['bytes'].to_i()
          data['url'] = match['url']
          data['user'] = match['user']
          data['method'] = match['method']
          
        }
      rescue => e
        $log.error("Unable to parse the line #{e}")
      end

      return time, data
    end   #def

   end   #class

end  #module
