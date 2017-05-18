#!/usr/bin/env bash
. /usr/stripe/bin/docker/stripe-init-build

cd /src
stripe-deps-ruby
stripe-build-ruby
#stripe-package-ruby

cd /build
stripe-test-ruby
