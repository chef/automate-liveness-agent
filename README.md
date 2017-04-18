# Automate Liveness Agent

Automate liveness agent sends keepalive messages to Chef Automate, which
prevents nodes that are up but not frequently running Chef Client from
appearing as "missing" in the Automate UI.

For more info about Chef Automate, see [https://www.chef.io/automate/](https://www.chef.io/automate/).

## Installation

Automate liveness agent is designed to be installed via Chef's "Required
Recipe" feature, which is in development. Check back later for full
instructions.

## Usage

Usage instructions will be made available once this software is
released.

## Development

After checking out the repo, run `bin/setup` to install dependencies. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports should be filed with your support representitive.

