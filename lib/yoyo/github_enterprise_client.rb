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

    def organization_member?(org, user)
      boolean_get("orgs/#{org}/members/#{user}")
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
      resp = excon_op(:delete, resource)

      if resp.status != 204
        msg = "Performed a DELETE action against resource '#{resource}' and didn't get a 204 back. Instead, got a #{resp.status}."
        $stderr.puts "WARN: #{msg}"
        Raven.capture_message(msg)
        return false
      end

      true
    end

    def get(resource)
      json_excon_op(:get, resource)
    end

    # These calls return a 204 if the resource is valid, 404 if invalid.
    def boolean_get(resource)
      resp = excon_op_without_error_checking(:get, resource)
      resp.status == 204
    end

    def put(resource)
      json_excon_op(:put, resource)
    end

    def paginate(resource)
      paginate_excon_op(:get, resource)
    end

    # Perform an excon operation, and return the HTTP body as an JSON object.
    def json_excon_op(method, resource, body=nil)
      resp = excon_op(method, resource, body)

      JSON.parse(resp.body) if resp.body.length > 0
    end

    # Perform an excon operation that supports pagination, and gets all of the
    # results for a resource.
    def paginate_excon_op(method, resource, body=nil)
      # Get the first page.
      resp = excon_op(method, resource)

      body = []
      if resp.body.length > 0
        body_obj = JSON.parse(resp.body)
        if body_obj.is_a?(Array)
          body.concat(body_obj)
        elsif body_obj.is_a?(Hash)
          body << body_obj
        else
          raise "Unknown object type #{body_obj.class} encountered!"
        end
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

    # Perform an Excon operation against a resource, returns the excon response
    # object. If the response indicates an error condition, data is logged to
    # Sentry and an error message is printed to `stderr` (but the response
    # object is still returned).
    def excon_op(method, resource, body=nil)
      resp = excon_op_without_error_checking(method, resource, body)

      begin
        if resp.status < 200 || resp.status > 299
          raise "ERROR: Got #{resp.status} from GitHub Enterprise for #{method} to resource '#{resource}'."
        end
      rescue => e
        if resp.body && resp.body.length > 0
          message_from_github = JSON.parse(resp.body)
        else
          message_from_github = "Unknown"
        end
        Raven.capture_exception(e, extra: {message_from_github: message_from_github})
        $stderr.puts e.message
        $stderr.puts "Message from GHE:", message_from_github
      end

      resp
    end

    # Perform an Excon operation against a resource, returns the excon response
    # object. This method doesn't check the response for any error conditions.
    def excon_op_without_error_checking(method, resource, body=nil)
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
        crumb.data = { response_status: resp.status }
        crumb.data[:response_body_length] = resp.body.length if resp.body
        crumb.category = "excon"
        crumb.timestamp = Time.now.to_i
        crumb.message = "Completed #{method.to_s.upcase} request to #{ghe_client.connection_uri}/#{path}"
      end

      resp
    end
  end
end
