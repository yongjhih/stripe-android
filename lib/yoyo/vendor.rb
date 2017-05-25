require 'mail'

module Yoyo
  module Vendor
    def self.is_vendor?(username)
      username.end_with?('-fcr') || username.end_with?('-voxpro')
    end
  end
end
