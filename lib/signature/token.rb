module Signature
  class Token
    attr_reader :key, :secret

    def initialize(key, secret)
      @key, @secret = key, secret
    end

    def sign(request)
      request.sign(self)
    end
  end
end
