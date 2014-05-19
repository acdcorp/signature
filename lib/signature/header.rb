module Signature
  module Header
    class Request < ::Signature::Request
      AUTH_HEADER_PREFIX = "X-API-"
      AUTH_HEADER_PREFIX_REGEX = /^X\-API\-(AUTH\-.+)$/

      def self.parse_headers headers={}
        hh = {}
        headers.each do |k,v|
          if match = k.upcase.match(AUTH_HEADER_PREFIX_REGEX)
            hh[match[1].downcase.gsub!('-', '_')] = v
          end
        end
        hh
      end

      def initialize method, path, query={}, headers={}
        auth_hash = self.class.parse_headers(headers)
        super(method, path, query.merge(auth_hash))
      end

      def sign token
        auth_hash = super(token)
        auth_hash.inject({}) do |memo, (k,v)|
          memo["#{AUTH_HEADER_PREFIX}#{k.to_s.upcase.gsub('_', '-')}"] = v
          memo
        end
      end
    end
  end
end
