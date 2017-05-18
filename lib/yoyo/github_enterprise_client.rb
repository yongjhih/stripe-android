require 'excon'
require 'json'
require 'sentry-raven'

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

    def organization_teams(org)
      paginate("orgs/#{org}/teams")
    end

    def add_team_membership(team_id, username)
      put("teams/#{team_id}/memberships/#{username}")
    end

    # Admin API
    def create_user(username, email)
      post('admin/users', {:login => username, :email => email})
    end

    private
    def post(resource, params)
      json_excon_op(:post, resource, params)
    end

    def delete(resource)
      json_excon_op(:delete, resource)
    end

    def get(resource)
      json_excon_op(:get, resource)
    end

    def put(resource)
      json_excon_op(:put, resource)
    end

    def paginate(resource)
      paginate_excon_op(:get, resource)
    end

    # Perform an excon operation, and return the HTTP body as an JSON object.
    def json_excon_op(method, resource, body=nil)
      resp = excon_op(method, resource, body=nil)
      JSON.parse(resp.body) if resp.body.length > 0
    end

    def paginate_excon_op(method, resource, body=nil)
      # Get the first page.
      resp = excon_op(method, resource)
      body = []
      if resp.body.length > 0
        body.concat(JSON.parse(resp.body))
      end

      # Dig out the "Link" header, and extract the `?page=2` part. If we can't
      # extract it, then there are no more pages, and we should stop.
      while resp.headers.fetch("Link", "") =~ /(\?[^>]+)>; rel="next"/
        resp = excon_op(method, "#{resource}#{$1}")
        if resp.body.length > 0
          body.concat(JSON.parse(resp.body))
        end
      end
      body
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

      Raven.breadcrumbs.record do |crumb|
        crumb.data = { response_env: resp }
        crumb.category = "excon"
        crumb.timestamp = Time.now.to_i
        crumb.message = "Completed #{method.to_s.upcase} request to #{ghe_client.connection_uri}/#{path}"
      end

      # FIXME(areitz): potentially remove this debug code when we figure out what's going on.
      if method == :delete && resp.status != 204
        Raven.capture_message("Performed a DELETE action and didn't get a 204 back. Instead, got #{resp.status}")
      end

      begin
        if resp.status < 200 || resp.status > 299
          raise "ERROR: Got #{resp.status} from GitHub Enterprise for #{method} to path '#{path}'."
        end
      rescue => e
        Raven.capture_exception(e)
        $stderr.puts e.message
      end

      resp
    end
  end
end
