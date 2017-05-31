require_relative '../_lib'

module Critic
  class GithubEnterpriseClientTest < Critic::Unit::Test
    describe "GitHub Enterprise Client Operations" do
      before do
        @ghe_client = Yoyo::GithubEnterpriseClient.new("sometoken")
      end

      def ghe_url(resource)
        "http://git.corp.stripe.com/api/v3/#{resource}"
      end

      def sample_response(title="areitz@stripe.com", key="ssh-rsa blah blah blah")
        <<-EOS
        [
          {
            "id": 7,
            "key": "#{key}",
            "url": "https://git.corp.stripe.com/api/v3/user/keys/7",
            "title": "#{title}",
            "verified": true,
            "created_at": "2017-01-04T22:19:42Z",
            "read_only": false
          }
        ]
        EOS
      end

      it "lists keys" do
        Excon.stub({:method => :get, :url => ghe_url('user/keys')}, {:body => sample_response, :status => 200})
        keys = @ghe_client.keys
        assert_equal(7, keys[0]['id'], "Id mis-match error")
      end

      it "adds a key" do
        sample_title = "some test key title"
        sample_key = "ssh-rsa aaabbbccc123"
        Excon.stub({:method => :post, :url => ghe_url('user/keys')}, {:body => sample_response(sample_title, sample_key), :status => 200})
        resp = @ghe_client.add_key(sample_title, sample_key)
        assert_equal(sample_title, resp[0]['title'], "Title mis-match error")
      end

      it "successfully removes a valid key" do
        Excon.stub({:method => :delete, :url => ghe_url('user/keys/71')}, {:body => "", :status => 204})
        assert(@ghe_client.remove_key(71), "Error removing key")
      end

      it "fails removing an invalid key" do
        Excon.stub({:method => :delete, :url => ghe_url('user/keys/71')}, {:body => nil, :status => 404})
        refute(@ghe_client.remove_key(71), "Error removing key")
      end

      it "lists teams in an org" do
        first_resp_body = <<-EOS
        [
          {
            "name": "textexpander-admin",
            "id": 299,
            "slug": "textexpander-admin",
            "description": "People with write access to the textexpander repo",
            "privacy": "closed",
            "url": "https://git.corp.stripe.com/api/v3/teams/299",
            "members_url": "https://git.corp.stripe.com/api/v3/teams/299/members{/member}",
            "repositories_url": "https://git.corp.stripe.com/api/v3/teams/299/repos",
            "permission": "pull"
          }
        ]
        EOS
        second_resp_body = <<-EOS
        [
          {
            "name": "data-platform",
            "id": 273,
            "slug": "data-platform",
            "description": "Dat big Data (fka data-infra)",
            "privacy": "closed",
            "url": "https://git.corp.stripe.com/api/v3/teams/273",
            "members_url": "https://git.corp.stripe.com/api/v3/teams/273/members{/member}",
            "repositories_url": "https://git.corp.stripe.com/api/v3/teams/273/repos",
            "permission": "pull"
          }
        ]
        EOS
        start_link_header = '<https://git.corp.stripe.com/api/v3/organizations/631/teams?page=2>; rel="next", <https://git.corp.stripe.com/api/v3/organizations/631/teams?page=5>; rel="last"'
        end_link_header = '<https://git.corp.stripe.com/api/v3/organizations/631/teams?page=1>; rel="first", <https://git.corp.stripe.com/api/v3/organizations/631/teams?page=4>; rel="prev"'

        # I had a pretty hard time mocking this out. The Excon docs state that:
        #
        #    "You can add whatever stubs you might like this way and they will be checked against
        #     in the order they were added, if none of them match then excon will raise an
        #     Excon::Errors::StubNotFound error to let you know."
        #
        # I wasn't able to get this to work. I tried stubbing out the first URL,
        # and a second URL that terminates the pagination, but Excon ignored the
        # second URL. So instead, I created a callback method, that inspected
        # the current path, and swapped around the body and headers returned.
        # Without doing this, pagination goes into an infinite loop.
        paginate_response_callback = lambda do |request_params|
          ret = {:status => 200}
          if request_params[:path] == "/api/v3/orgs/stripe-internal/teams"
            ret[:body] = first_resp_body
            ret[:headers] = {'Link' => start_link_header}
          elsif request_params[:path] == "/api/v3/orgs/stripe-internal/teams?page=2"
            ret[:body] = second_resp_body
            ret[:headers] = {'Link' => end_link_header}
          else
            raise "Invalid URL encountered"
          end
          ret
        end
        Excon.stub({:method => :get}, paginate_response_callback)

        resp = @ghe_client.organization_teams('stripe-internal')
        assert_equal(2, resp.length, "Didn't get two team objects")
        assert_equal(299, resp[0]['id'], "First team_id is wrong")
        assert_equal(273, resp[1]['id'], "Second team_id is wrong")
      end

      it "returns true if a person is in an org" do
        org = 'stripe-internal'
        user = 'areitz-test'
        Excon.stub({:method => :get, :url => ghe_url("orgs/#{org}/members/#{user}")}, {:body => nil, :status => 204})
        assert(@ghe_client.organization_member?(org, user), "Member should be in org")
      end

      it "returns false if a person is not in an org" do
        org = 'stripe-internal'
        user = 'areitz-test'
        Excon.stub({:method => :get, :url => ghe_url("orgs/#{org}/members/#{user}")}, {:body => nil, :status => 404})
        refute(@ghe_client.organization_member?(org, user), "Member should not be in org")
      end

      it "adds a person to a team" do
        team_id = 1234
        user = 'areitz-test'
        team_add_resp_body = <<-EOS
        {
          "state": "active",
          "role": "member",
          "url": "https://git.corp.stripe.com/api/v3/teams/314/memberships/areitz-test"
        }
        EOS
        Excon.stub({:method => :put, :url => ghe_url("teams/#{team_id}/memberships/#{user}")}, {:body => team_add_resp_body, :status => 204})
        resp = @ghe_client.add_team_membership(team_id, user)
        assert_equal('active', resp['state'], "Got invalid state")
      end

      it "creates a new user" do
        create_user_resp_body = <<-EOS
        {
          "login": "areitz-test2",
          "id": 1267,
          "avatar_url": "https://git.corp.stripe.com/avatars/u/1267?",
          "gravatar_id": "",
          "url": "https://git.corp.stripe.com/api/v3/users/areitz-test2",
          "html_url": "https://git.corp.stripe.com/areitz-test2",
          "followers_url": "https://git.corp.stripe.com/api/v3/users/areitz-test2/followers",
          "following_url": "https://git.corp.stripe.com/api/v3/users/areitz-test2/following{/other_user}",
          "gists_url": "https://git.corp.stripe.com/api/v3/users/areitz-test2/gists{/gist_id}",
          "starred_url": "https://git.corp.stripe.com/api/v3/users/areitz-test2/starred{/owner}{/repo}",
          "subscriptions_url": "https://git.corp.stripe.com/api/v3/users/areitz-test2/subscriptions",
          "organizations_url": "https://git.corp.stripe.com/api/v3/users/areitz-test2/orgs",
          "repos_url": "https://git.corp.stripe.com/api/v3/users/areitz-test2/repos",
          "events_url": "https://git.corp.stripe.com/api/v3/users/areitz-test2/events{/privacy}",
          "received_events_url": "https://git.corp.stripe.com/api/v3/users/areitz-test2/received_events",
          "type": "User",
          "site_admin": false
        }
        EOS
        Excon.stub({:method => :post, :url => ghe_url("admin/users")}, {:body => create_user_resp_body, :status => 201})
        resp = @ghe_client.create_user('areitz-test', 'areitz+test-user@stripe.com')
        assert_equal('User', resp['type'], "Received invalid response")
      end
    end
  end
end
