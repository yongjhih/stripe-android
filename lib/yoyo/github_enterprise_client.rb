require 'excon'
require 'json'

module Yoyo
  # Class that contains helper methods for interacting with GitHub Enterprise.
  # We don't yet have Octokit working through certproxy, so instead this
  # implements the methods of the GitHub API that Yoyo needs for full
  # functionality. This class can be deprecated after we come up with a good
  # solution to https://jira.corp.stripe.com/browse/ITOOLS-1169
  class GithubEnterpriseClient

    attr_reader :ghe_client
    attr_reader :api_token

    # Create a new object instance. Takes a GitHub Enterprise Personal Access
    # Token (API Token) from a user on GHE.
    def initialize(token)
      @api_token = token

      # Configure an Excon connection that leverages the local certproxy.
      @ghe_client ||= Excon.new("http://git.corp.stripe.com",
                                 proxy: {scheme: 'unix', path: "#{ENV['HOME']}/.stripeproxy"},
                                 persistent: true)
    end

    # List all SSH keys on the account.
    def keys
      get('user/keys')
    end

    # Add an SSH key to an account.
    def add_key(title, key)
      post('user/keys', {:title => title, :key => key})
    end

    # Remove an SSH key from an account.
    def remove_key(id)
      delete("user/keys/#{id}")
    end

    private
    def post(resource, params)
      excon_op(:post, resource, params)
    end

    def delete(resource)
      excon_op(:delete, resource)
    end

    def get(resource)
      excon_op(:get, resource)
    end

    # Perform an Excon operation.
    def excon_op(method, resource, body=nil)
      path = "/api/v3/#{resource}"
      headers = {
        'Accept' => 'application/vnd.github.v3+json',
        'Authorization' => "token #{api_token}"
      }
      if method == :post
        headers['Content-Type'] = 'application/json'
        resp = ghe_client.request(
          method: method,
          path: path,
          body: body.to_json,
          headers: headers,
        )
      else
        resp = ghe_client.request(
          method: method,
          path: path,
          headers: headers,
        )
      end

      if resp.status < 200 || resp.status > 299
        raise "ERROR: Got #{resp.status} from GitHub Enterprise for #{method} to path '#{path}'."
      end
      JSON.parse(resp.body) if resp.body.length > 0
    end
  end
end
